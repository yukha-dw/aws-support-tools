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

from aws_clients import AWSClients
from report_writer import ReportWriter
from datetime import datetime, timedelta, timezone

class CloudWatchVerifier:
    '''
    Class to verify that MWAA environment metrics exposed in CloudWatch are healthy.
    '''
    def __init__(self, clients: AWSClients, report: ReportWriter, env):
        self.cw = clients.cw
        self.report = report
        self.env = env

    def check_celery_sqs_health(self):
        '''
        Check CloudWatch metrics for task queue activity (TaskQueued, TaskPulled, TaskExecuted)
        over the last 24 hours and worker heartbeats over the last 20 minutes.
        '''
        self.report.write_all_locations("### Checking Celery executor SQS queue health...")
        metrics = ["TaskQueued", "TaskPulled", "TaskExecuted"]
        dimensions = [
                {
                    "Name": "Environment",
                    "Value": self.env["Name"]
                },
                {
                    "Name": "Function",
                    "Value": "Celery"
                }
            ]
        
        for metric in metrics:
            response = self.cw.get_metric_statistics(
                Namespace="AmazonMWAA",
                MetricName=metric,
                Dimensions=dimensions,
                StartTime=datetime.now(timezone.utc) - timedelta(hours=24),
                EndTime=datetime.now(timezone.utc),
                Period=300,  # 5 minutes
                Statistics=["Average"]
            )

            # Find the latest datapoint
            if response["Datapoints"]:
                latest = max(response["Datapoints"], key=lambda x: x["Timestamp"])
                delta = datetime.now(timezone.utc) - latest['Timestamp']
                hours = int(delta.total_seconds() // 3600)
                minutes = int((delta.total_seconds() % 3600) // 60)
                self.report.write_all_locations(f"{metric} Latest Datapoint - {hours}h {minutes}m ago - Time: {latest['Timestamp']}, Value: {latest['Average']}")
            else:
                self.report.write_all_locations(f"⚠️ {metric} did not have any datapoints in last 24 hours.")

        response = self.cw.get_metric_statistics(
            Namespace="AmazonMWAA",
            MetricName="CeleryWorkerHeartbeat",
            Dimensions=dimensions,
            StartTime=datetime.now(timezone.utc) - timedelta(minutes=20),
            EndTime=datetime.now(timezone.utc),
            Period=300,  # 5 minutes
            Statistics=["Average"]
        )

        if response["Datapoints"]:
            self.report.write_all_locations("✅ Celery worker heartbeat received in last 20 minutes.")
        else:
            self.report.write_all_locations("🚫 No Celery Worker heartbeat received in last 20 minutes")

    def check_environment_class_utilization(self):
        '''
        For one of BaseWorker, Scheduler, or WebServer clusters,
        if the average CPU Utilization or Memory Utilization for 
        last 7 days is above a certain percentage, suggest upgrade.

        https://docs.aws.amazon.com/mwaa/latest/userguide/environment-class.html
        '''
        self.report.write_all_locations("### Environment Class - Cluster Utilization")
        THRESHOLD = 85

        clusters = ["BaseWorker", "Scheduler", "WebServer"]
        metrics = ["CPUUtilization", "MemoryUtilization"]
        env_classes = ["mw1.micro", "mw1.small", "mw1.medium", "mw1.large", "mw1.xlarge", "mw1.2xlarge"]

        suggest_upgrade = False
        for metric in metrics:
            for cluster in clusters:
                dimensions = [
                    {
                        "Name": "Environment",
                        "Value": self.env["Name"]
                    },
                    {
                        "Name": "Cluster",
                        "Value": cluster
                    }
                ]

                response = self.cw.get_metric_statistics(
                    Namespace="AWS/MWAA",
                    MetricName=metric,
                    Dimensions=dimensions,
                    StartTime=datetime.now(timezone.utc) - timedelta(days=7),
                    EndTime=datetime.now(timezone.utc),
                    Period=604800,  # 7 days
                    Statistics=["Average"]
                )

                if response["Datapoints"][0]["Average"] > THRESHOLD:
                    suggest_upgrade = True
                    self.report.write_all_locations("⚠️ The", cluster, "cluster had an average", metric, "of",
                                            int(response["Datapoints"][0]["Average"]), response["Datapoints"][0]["Unit"].lower(),
                                            "over last 7 days. MWAA recommends this value to be less than", THRESHOLD, "percent.")
                else:
                    self.report.write_full_report("✅ The", cluster, "cluster had an average", metric, "of",
                                            int(response["Datapoints"][0]["Average"]), response["Datapoints"][0]["Unit"].lower(),
                                            "over last 7 days. This is under the MWAA recommended threshold of", THRESHOLD, "percent.")

        if suggest_upgrade:
            if self.env["EnvironmentClass"] == env_classes[-1]:
                self.report.write_all_locations("⚠️ Your utilization is higher than the threshold although you use the largest environment class.")
                self.report.write_all_locations("Consider MWAA best practices for performance tuning: https://docs.aws.amazon.com/mwaa/latest/userguide/best-practices-tuning.html")
            else:
                self.report.write_all_locations("⚠️ MWAA recommends the environment class to be upgraded to " + env_classes[env_classes.index(self.env["EnvironmentClass"]) + 1])
                self.report.write_all_locations("You can also consider MWAA best practices for performance tuning: https://docs.aws.amazon.com/mwaa/latest/userguide/best-practices-tuning.html")
        else:
            self.report.write_all_locations("✅ The average CPU and memory utilizations of all clusters were under the threshold of", THRESHOLD, "percent for the last 7 days.")

    def check_environment_class_dag_count(self):
        '''
        Suggest the use of a specific environment class based on the number
        of DAGs present in the environment. The following link outlines the
        DAG capacity of different environment classes:

        https://docs.aws.amazon.com/mwaa/latest/userguide/environment-class.html
        '''
        self.report.write_all_locations("### Environment Class - DAG Count")
        env_class_dag_capacities = [
            ("mw1.micro", 25),
            ("mw1.small", 50),
            ("mw1.medium", 250),
            ("mw1.large", 1000),
            ("mw1.xlarge", 2000),
            ("mw1.2xlarge", 4000)
        ]

        dimensions = [
            {
                "Name": "Environment",
                "Value": self.env["Name"]
            },
            {
                "Name": "Function",
                "Value": "DAG Processing"
            }
        ]

        response = self.cw.get_metric_statistics(
            Namespace="AmazonMWAA",
            MetricName="DagBagSize",
            Dimensions=dimensions,
            StartTime=datetime.now(timezone.utc) - timedelta(minutes=6),
            EndTime=datetime.now(timezone.utc),
            Period=300,  # 5 minutes
            Statistics=["Average"]
        )

        dagcount = int(response["Datapoints"][0]["Average"])
        self.report.write_all_locations("Dag count:", dagcount)

        current_capacity = 0
        for env_class, capacity in env_class_dag_capacities:
            if self.env["EnvironmentClass"] == env_class:
                current_capacity = capacity
                break

        if dagcount > current_capacity:
            self.report.write_all_locations("⚠️ The DAG count exceeds the capacity of the environment class. Consider upgrading to a larger environment class.")
        else:
            self.report.write_all_locations("✅ The DAG count is within the capacity of the", self.env["EnvironmentClass"], "environment class.")

if __name__ == "__main__":
    clients = AWSClients()
    report = ReportWriter()
    verifier = CloudWatchVerifier(clients, report)
    verifier.check_celery_sqs_health(clients.mwaa_env)
    verifier.check_environment_class_utilization(clients.mwaa_env)
    verifier.check_environment_class_dag_count(clients.mwaa_env)
    report.close()