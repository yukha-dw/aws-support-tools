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

class IAMVerifier:
    def __init__(self, clients: AWSClients, report: ReportWriter, env, partition, region, env_name, top_level_domain):
        self.iam = clients.iam
        self.report = report
        self.partition = partition
        self.region = region
        self.env_name = env_name
        self.top_level_domain = top_level_domain
        self.env = env

    def check_iam_permissions(self):
        '''uses iam simulation to check permissions of the role assigned to the environment'''
        self.report.write_all_locations("### IAM Permissions")
        self.report.write_all_locations('Checking the IAM execution role', self.env['ExecutionRoleArn'], 'using iam policy simulation')
        account_id = get_account_id(self.env)
        policies = self.iam.list_attached_role_policies(
            RoleName=self.env['ExecutionRoleArn'].split("/")[-1]
        )['AttachedPolicies']
        policy_list = []
        for policy in policies:
            policy_arn = policy['PolicyArn']
            policy_version = self.iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_doc = self.iam.get_policy_version(PolicyArn=policy_arn,
                                                    VersionId=policy_version)['PolicyVersion']['Document']
            policy_list.append(json.dumps(policy_doc))
        eval_results = []
        # Add inline policies
        policy_list.extend(get_inline_policies(self.iam, self.env['ExecutionRoleArn'].split("/")[-1]))
        if "KmsKey" in self.env:
            self.report.write_full_report('Found Customer managed CMK')
            if self.partition != 'aws-cn':
                eval_results = eval_results + self.iam.simulate_custom_policy(
                    PolicyInputList=policy_list,
                    ActionNames=[
                        "airflow:PublishMetrics"
                    ],
                    ResourceArns=[
                        self.env['Arn']
                    ]
                )['EvaluationResults']
            # this next test should be denied
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "s3:ListAllMyBuckets"
                ],
                ResourceArns=[
                    self.env['SourceBucketArn'],
                    self.env['SourceBucketArn'] + '/'
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "s3:GetObject*",
                    "s3:GetBucket*",
                    "s3:List*"
                ],
                ResourceArns=[
                    self.env['SourceBucketArn'],
                    self.env['SourceBucketArn'] + '/'
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents",
                    "logs:GetLogEvents",
                    "logs:GetLogRecord",
                    "logs:GetLogGroupFields",
                    "logs:GetQueryResults"
                ],
                ResourceArns=[
                    "arn:" + self.partition + ":logs:" + self.region + ":" + account_id + ":log-group:airflow-" + self.env_name + "-*"
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "logs:DescribeLogGroups"
                ],
                ResourceArns=[
                    "*"
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "cloudwatch:PutMetricData"
                ],
                ResourceArns=[
                    "*"
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "sqs:ChangeMessageVisibility",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                    "sqs:GetQueueUrl",
                    "sqs:ReceiveMessage",
                    "sqs:SendMessage"
                ],
                ResourceArns=[
                    "arn:" + self.partition + ":sqs:" + self.region + ":*:airflow-celery-*"
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "kms:GenerateDataKey*"
                ],
                ResourceArns=[
                    self.env['KmsKey']
                ],
                ContextEntries=[
                    {
                        'ContextKeyName': 'kms:viaservice',
                        'ContextKeyValues': [
                            's3.' + self.region + self.top_level_domain
                        ],
                        'ContextKeyType': 'string'
                    }
                ],
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "kms:GenerateDataKey*"
                ],
                ResourceArns=[
                    self.env['KmsKey']
                ],
                ContextEntries=[
                    {
                        'ContextKeyName': 'kms:viaservice',
                        'ContextKeyValues': [
                            'sqs.' + self.region + '.amazonaws.com',
                        ],
                        'ContextKeyType': 'string'
                    }
                ],
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt"
                ],
                ResourceArns=[
                    self.env['KmsKey']
                ],
                ContextEntries=[
                    {
                        'ContextKeyName': 'kms:viaservice',
                        'ContextKeyValues': [
                            's3.' + self.region + '.amazonaws.com'
                        ],
                        'ContextKeyType': 'string'
                    }
                ],
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt"
                ],
                ResourceArns=[
                    self.env['KmsKey']
                ],
                ContextEntries=[
                    {
                        'ContextKeyName': 'kms:viaservice',
                        'ContextKeyValues': [
                            'sqs.' + self.region + '.amazonaws.com'
                        ],
                        'ContextKeyType': 'string'
                    }
                ],
            )['EvaluationResults']
        else:
            self.report.write_full_report('Using AWS CMK')
            if self.partition != 'aws-cn':
                eval_results = eval_results + self.iam.simulate_custom_policy(
                    PolicyInputList=policy_list,
                    ActionNames=[
                        "airflow:PublishMetrics"
                    ],
                    ResourceArns=[
                        self.env['Arn']
                    ]
                )['EvaluationResults']
            # this action should be denied
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "s3:ListAllMyBuckets"
                ],
                ResourceArns=[
                    self.env['SourceBucketArn'],
                    self.env['SourceBucketArn'] + '/'
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "s3:GetObject*",
                    "s3:GetBucket*",
                    "s3:List*"
                ],
                ResourceArns=[
                    self.env['SourceBucketArn'],
                    self.env['SourceBucketArn'] + '/'
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents",
                    "logs:GetLogEvents",
                    "logs:GetLogRecord",
                    "logs:GetLogGroupFields",
                    "logs:GetQueryResults"
                ],
                ResourceArns=[
                    "arn:" + self.partition + ":logs:" + self.region + ":" + account_id + ":log-group:airflow-" + self.env_name + "-*"
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "logs:DescribeLogGroups"
                ],
                ResourceArns=[
                    "*"
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "cloudwatch:PutMetricData"
                ],
                ResourceArns=[
                    "*"
                ]
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "sqs:ChangeMessageVisibility",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                    "sqs:GetQueueUrl",
                    "sqs:ReceiveMessage",
                    "sqs:SendMessage"
                ],
                ResourceArns=[
                    "arn:" + self.partition + ":sqs:" + self.region + ":*:airflow-celery-*"
                ]
            )['EvaluationResults']
            # tests role to allow any kms all for resources not in this account and that are from the sqs service
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt"
                ],
                ResourceArns=[
                    "arn:" + self.partition + ":kms:*:111122223333:key/*"
                ],
                ContextEntries=[
                    {
                        'ContextKeyName': 'kms:viaservice',
                        'ContextKeyValues': [
                            'sqs.' + self.region + '.amazonaws.com',
                        ],
                        'ContextKeyType': 'string'
                    }
                ],
            )['EvaluationResults']
            eval_results = eval_results + self.iam.simulate_custom_policy(
                PolicyInputList=policy_list,
                ActionNames=[
                    "kms:GenerateDataKey*"
                ],
                ResourceArns=[
                    "arn:" + self.partition + ":kms:*:111122223333:key/*"
                ],
                ContextEntries=[
                    {
                        'ContextKeyName': 'kms:viaservice',
                        'ContextKeyValues': [
                            'sqs.' + self.region + '.amazonaws.com',
                        ],
                        'ContextKeyType': 'string'
                    }
                ],
            )['EvaluationResults']

        iam_issue_detected = False
        for eval_result in eval_results:
            # s3:ListAllMyBuckets should be denied. Raise an issue if it is not.
            if eval_result['EvalActionName'] == "s3:ListAllMyBuckets":
                if eval_result['EvalDecision'] != 'allowed':
                    self.report.write_full_report('✅', "Action", eval_result['EvalActionName'], "is blocked successfully on resource", eval_result['EvalResourceName'])
                else:
                    self.report.write_all_locations('🚫', "MWAA expects action", eval_result['EvalActionName'], "to be blocked on resource", eval_result['EvalResourceName'], "but it is not blocked.")
                    iam_issue_detected = True
            # Other policies should be allowed.
            elif eval_result['EvalDecision'] != 'allowed':
                self.report.write_all_locations("🚫", "MWAA expects action", eval_result['EvalActionName'], "to be allowed on resource", eval_result['EvalResourceName'], "but it is not allowed.")
                self.report.write_all_locations("Failed with the following eval decision:", eval_result['EvalDecision'])
                iam_issue_detected = True
            elif eval_result['EvalDecision'] == 'allowed':
                self.report.write_full_report('✅', "Action", eval_result['EvalActionName'], "is allowed on resource", eval_result['EvalResourceName'])
            else:
                self.report.write_all_locations("There is a result with unknown fields:", eval_result)
        
        if iam_issue_detected:
            self.report.write_all_locations('⚠️ You can investigate the detected policy issue more at')
            self.report.write_all_locations("https://policysim.aws.amazon.com/home/index.jsp?#roles/" + self.env['ExecutionRoleArn'].split("/")[-1])
        else:
            self.report.write_all_locations('✅ All IAM policies are as expected.')
        self.report.write_full_report('These simulations are based off of the sample policies here:')
        self.report.write_full_report('https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html#mwaa-create-role-json\n')

