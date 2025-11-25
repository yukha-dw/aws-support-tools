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
import time
from datetime import datetime, timedelta
from aws_clients import AWSClients
from report_writer import ReportWriter

class LogsVerifier:
    def __init__(self, clients: AWSClients, report: ReportWriter, env, env_name):
        self.logs = clients.logs
        self.cloudtrail = clients.cloudtrail
        self.report = report
        self.env = env
        self.log_groups = self.logs.describe_log_groups(
            logGroupNamePrefix='airflow-'+ env_name
        )['logGroups']

    def check_log_groups(self):
        '''check if cloudwatch log groups exists, if not check cloudtrail to see why they weren't created'''
        num_of_enabled_log_groups = sum(
            self.env['LoggingConfiguration'][logConfig]['Enabled'] is True
            for logConfig in self.env['LoggingConfiguration']
        )
        num_of_found_log_groups = len(self.log_groups)
        self.report.write_all_locations('### Log groups')
        if num_of_found_log_groups < num_of_enabled_log_groups:
            self.report.write_all_locations('🚫 The number of log groups is less than the number of enabled suggesting an error.')
            self.report.write_all_locations('checking cloudtrail for CreateLogGroup/DeleteLogGroup requests...\n')
            events = self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'CreateLogGroup'
                    },
                ],
                StartTime=self.env['CreatedAt'] - timedelta(minutes=15),
                EndTime=self.env['CreatedAt']
            )['Events']
            events = events + self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'DeleteLogGroup'
                    },
                ],
                StartTime=self.env['CreatedAt'] - timedelta(minutes=15),
                EndTime=self.env['CreatedAt']
            )['Events']
            events = events + self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'DeleteLogGroup'
                    },
                ],
                StartTime=datetime.now() - timedelta(minutes=30),
                EndTime=datetime.now()
            )['Events']
            for event in events:
                self.report.write_all_locations('Found CloudTrail event: ', event)
            self.report.write_all_locations('if events are failing, try creating the log groups manually\n')
        else:
            self.report.write_all_locations("✅ Number of log groups match suggesting they've been created successfully.")

    def check_for_failing_logs(self):
        '''look for any failing logs from CloudWatch in the past hour'''
        self.report.write_all_locations("### Failing Cloudwatch Logs\nChecking CloudWatch logs for any errors less than 1 hour old")
        now = int(time.time() * 1000)
        past_day = now - 3600000
        for log in self.log_groups:
            events = self.logs.filter_log_events(
                logGroupName=log['logGroupName'],
                startTime=past_day,
                endTime=now,
                filterPattern='?ERROR ?Error ?error ?traceback ?Traceback ?exception ?Exception ?fail ?Fail'
            )['events']
            events = sorted(events, key=lambda i: i['timestamp'])
            self.report.write_all_locations('Log group: ', log['logGroupName'])
            if len(events) == 0:
                self.report.write_all_locations('✅ No error logs found in the past hour')
                continue
            self.report.write_all_locations('⚠️ Please see the full report for logs.')
            for event in events:
                self.report.write_full_report(str(event['timestamp']) + " " + event['message'], end='')
