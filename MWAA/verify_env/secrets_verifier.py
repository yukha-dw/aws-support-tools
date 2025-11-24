# This Python file uses the following encoding: utf-8
'''
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''
import json
from aws_clients import AWSClients
from report_writer import ReportWriter
from utils import get_account_id, get_inline_policies

class SecretsVerifier:
    def __init__(self, clients: AWSClients, report: ReportWriter, env):
        self.iam = clients.iam
        self.kms = clients.kms
        self.report = report
        self.env = env

    def check_secrets_manager_iam(self):
        account_id = get_account_id(self.env)
        policies = self.iam.list_attached_role_policies(
            RoleName=self.env["ExecutionRoleArn"].split("/")[-1]
        )["AttachedPolicies"]

        policy_list = []
        for policy in policies:
            policy_arn = policy["PolicyArn"]
            policy_version = self.iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_doc = self.iam.get_policy_version(PolicyArn=policy_arn,
                                                    VersionId=policy_version)['PolicyVersion']['Document']
            policy_list.append(json.dumps(policy_doc))
        policy_list.extend(get_inline_policies(self.iam, self.env['ExecutionRoleArn'].split("/")[-1]))

        # Because we don't know the names of the secrets user set up for airflow,
        # we cannot use policy simulations. Instead, we check if the action is included
        # in the policy document.
        required_actions = [
            "secretsmanager:GetResourcePolicy",
            "secretsmanager:GetSecretValue", 
            "secretsmanager:DescribeSecret",
            "secretsmanager:ListSecretVersionIds",
            "secretsmanager:ListSecrets"
        ]

        all_actions = []
        for policy_json in policy_list:
            policy = json.loads(policy_json)
            for statement in policy.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    all_actions += actions

        found = []
        not_found = []
        for act in required_actions:
            if act in all_actions:
                found.append(act)
            else:
                not_found.append(act)
        return found, not_found

    def check_secrets_manager_config(self):
        secrets_backend = self.env["AirflowConfigurationOptions"].get("secrets.backend", None)
        secrets_backend_kwargs = self.env["AirflowConfigurationOptions"].get("secrets.backend_kwargs", None)
        if (secrets_backend is None) or (secrets_backend_kwargs is None):
            return False

        if secrets_backend != "airflow.providers.amazon.aws.secrets.secrets_manager.SecretsManagerBackend":
            return False
        
        if ("connections_prefix" not in secrets_backend_kwargs) or ("variables_prefix" not in secrets_backend_kwargs):
            return False
            
        return True

    def check_secrets_manager(self):
        '''
        There are five steps needed to connect AWS Secrets Manager with
        the Airflow environment. These steps are outlined in the following
        document. This function checks that the first two steps are completed
        correctly.
        
        https://docs.aws.amazon.com/mwaa/latest/userguide/connections-secrets-manager.html#connections-sm-aa-uri
        '''
        self.report.write_all_locations("### AWS Secrets Manager")
        _, not_found_actions = self.check_secrets_manager_iam()
        iam_check_passed = len(not_found_actions) == 0
        config_check_passed = self.check_secrets_manager_config()

        # The user might not be using secrets manager, so only output error if one check passes and other fails
        if iam_check_passed and config_check_passed:
            self.report.write_all_locations("✅ AWS Secrets Manager is configured correctly.")
        elif config_check_passed:
            self.report.write_all_locations("🚫 AWS Secrets Manager is not configured correctly. Please check that the execution role has the correct IAM permissions.")
            self.report.write_all_locations("The following actions are missing from the execution role's policy:")
            for action in not_found_actions:
                self.report.write_all_locations("   ", action)
            self.report.write_all_locations("https://docs.aws.amazon.com/mwaa/latest/userguide/connections-secrets-manager.html#connections-sm-policy")
        elif iam_check_passed:
            self.report.write_all_locations("🚫 AWS Secrets Manager is not configured correctly. Please check that the Airflow configuration for the secrets backend is correct.")
            self.report.write_all_locations("https://docs.aws.amazon.com/mwaa/latest/userguide/connections-secrets-manager.html#connections-sm-aa-configuration")
        else:
            self.report.write_all_locations("AWS Secrets Manager is not being used. This is not necessarily an error since the use of secrets manager is optional.")

    def check_kms_key_policy(self):
        '''
        check kms key and if its customer managed if it has a policy like this
        https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html#mwaa-create-role-json
        '''
        self.report.write_all_locations("### KMS Key Policy")
        if "KmsKey" in self.env:
            self.report.write_all_locations("Checking the kms key policy and if it includes reference to airflow")
            policy = self.kms.get_key_policy(
                KeyId=self.env['KmsKey'],
                PolicyName='default'
            )['Policy']
            if "airflow" not in policy and "aws:logs:arn" not in policy:
                self.report.write_all_locations("🚫", "MWAA expects texts 'airflow' and 'logs' to appear in KMS key policy but diagnostics cannot find them. Please check KMS key: ",
                    self.env['KmsKey'])
                self.report.write_all_locations("For an example resource policy, please see this doc: ")
                self.report.write_all_locations("https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html#mwaa-create-role-json \n")
            else:
                self.report.write_all_locations("✅", "KMS key policy includes text 'airflow' and 'logs' as expected.")
        else:
            self.report.write_all_locations("No KMS key is found in environment configuration. KMS Key is not always required, so this finding does not indicate an issue by itself.")
