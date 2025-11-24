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
import os
from datetime import datetime, timezone

class ReportWriter:
    """
    A utility class for managing diagnostic report output to both files and console.
    
    This class handles the creation and management of two types of diagnostic reports:
    1. Full Report: Comprehensive diagnostic information including all test results
    2. Key Findings: Summary of critical issues and important findings
    
    The class provides interactive prompts to allow users to choose whether to write
    reports to files or display them on standard output. It automatically generates
    unique filenames with timestamps to prevent conflicts.
    
    Example:
        >>> report = ReportWriter()
        Do you allow the results to be written to the following file: MWAA_DIAGNOSTICS_FULL_REPORT_17Sep2025_1045UTC.md?
        If you select no, the same information will be written to standard output.
        (Y/n): y
        
        >>> report.write_full_report("Test completed successfully")
        >>> report.write_key_findings("Critical issue found")
        >>> report.close()
    """
    def __init__(self):
        self.full_report_file = None
        self.key_findings_file = None

        self.full_report_path = self._generate_unique_filepath("MWAA_DIAGNOSTICS_FULL_REPORT", ".md")
        self.key_findings_path = self._generate_unique_filepath("MWAA_DIAGNOSTICS_KEY_FINDINGS", ".md")
        
        self.full_report_requested = False
        print("Do you allow the results to be written to the following file: " + self.full_report_path + "?")
        print("If you select no, the same information will be written to standard output.")
        if input("(Y/n):").lower().strip() in ["y", "yes", ""]:
            print()
            self.full_report_requested = True
            self.full_report_file = self._setup_report_file("MWAA Diagnostics Full Report", self.full_report_path)

        self.key_findings_requested = False
        print("Do you allow key findings to be written to the following file: " + self.key_findings_path + "?")
        print("If you select no, the same information will be written to standard output.")
        if input("(Y/n):").lower().strip() in ["y", "yes", ""]:
            print()
            self.key_findings_requested = True
            self.key_findings_file = self._setup_report_file("MWAA Diagnostics Key Findings", self.key_findings_path)

    @staticmethod
    def _generate_unique_filepath(base_name, ext):
        """
        Generate a unique file path with timestamp to avoid file conflicts.
        If a file with the generated name already exists, appends a counter to ensure
        uniqueness. Tries up to 1000 variations before giving up.
        
        Args:
            base_name (str): Base name for the file (e.g., "MWAA_DIAGNOSTICS_FULL_REPORT")
            ext (str): File extension including the dot (e.g., ".md")
        
        Returns:
            str: Unique file path in the current working directory
        
        Raises:
            SystemExit: If unable to generate a unique filename after 1000 attempts
        
        Example:
            >>> path = ReportWriter._generate_unique_filepath("TEST_REPORT", ".txt")
            >>> print(path)
            /current/dir/TEST_REPORT_17Sep2025_1045UTC.txt
        """
        counter = 0
        while counter < 1000:
            name = base_name + "_" + datetime.now(timezone.utc).strftime("%d%b%Y_%H%M") + "UTC"
            if counter > 0:
                name = name + "_" + str(counter)
            name += ext
            path = os.path.join(os.getcwd(), name)
            if not os.path.exists(path):
                return path
            counter += 1
        print("Could not generate unique filepath. Exiting...")
        exit(1)

    @staticmethod
    def _setup_report_file(name, path):
        """
        Opens a file for writing and adds a markdown header with the report name
        and current UTC timestamp. The file is left open for subsequent writes.
        
        Args:
            name (str): Human-readable name for the report (e.g., "MWAA Diagnostics Full Report")
            path (str): File path where the report should be created
        
        Returns:
            file (object): Open file handle ready for writing
        
        Example:
            >>> file_handle = ReportWriter._setup_report_file("Test Report", "/tmp/test.md")
            >>> # File now contains:
            >>> # # Test Report
            >>> # 
            >>> # Date: 17 Sep 2025 10:45 UTC
        """
        file = open(path, "w")
        file.write("# " + name + "\n\n")
        file.write("Date: " + datetime.now(timezone.utc).strftime("%d %b %Y %H:%M") + " UTC\n\n")
        return file

    def write_full_report(self, *args, sep=' ', end='\n\n'):
        """
        Write detailed diagnostic information to the full report.
        
        Outputs either to the full report file (if user opted for file output)
        or to standard output.
        
        Args:
            *args: Variable number of arguments to be written
            sep (str, optional): Separator between arguments. Defaults to ' '
            end (str, optional): String appended after the last argument. Defaults to '\n\n'
        
        Example:
            >>> report.write_full_report("Checking security group:", "sg-12345")
            >>> report.write_full_report("Status", "PASSED", sep=": ")
        """
        text = sep.join(str(arg) for arg in args) + end
        if self.full_report_requested:
            self.full_report_file.write(text)
        else:
            print(*args, sep=sep, end=end)

    def write_key_findings(self, *args, sep=' ', end='\n\n'):
        """
        Write critical findings and important issues to the key findings report.
        
        Outputs either to the key findings file (if user opted for file output)
        or to standard output.
        
        Args:
            *args: Variable number of arguments to be written
            sep (str, optional): Separator between arguments. Defaults to ' '
            end (str, optional): String appended after the last argument. Defaults to '\n\n'
        
        Example:
            >>> report.write_key_findings("🚫 Critical issue found in IAM permissions")
            >>> report.write_key_findings("✅ All security groups configured correctly")
        """
        text = sep.join(str(arg) for arg in args) + end
        if self.key_findings_requested:
            self.key_findings_file.write(text)
        else:
            print(*args, sep=sep, end=end)

    def write_all_locations(self, *args, sep=' ', end='\n\n'):
        """
        Write information to all output locations: both reports and console.
        
        Outputs the same information to the key findings file, full report file
        (if user opted for file outputs), and standard output.
        
        Args:
            *args: Variable number of arguments to be written
            sep (str, optional): Separator between arguments. Defaults to ' '
            end (str, optional): String appended after the last argument. Defaults to '\n\n'
        
        Example:
            >>> report.write_all_locations("### Starting IAM Permission Check")
            >>> report.write_all_locations("🚫 CRITICAL: Environment configuration invalid")
        """
        text = sep.join(str(arg) for arg in args) + end
        if self.key_findings_requested:
            self.key_findings_file.write(text)
        if self.full_report_requested:
            self.full_report_file.write(text)
        print(*args, sep=sep, end=end)


    def close(self):
        """
        Close all open report files and display file locations to user.
                
        Should be called in a try/finally block or similar error handling
        to ensure files are closed even if an exception occurs during
        diagnostic operations.
        
        Example:
            >>> report = ReportWriter()
            ... report.close()
            📝 Full report is written to MWAA_DIAGNOSTICS_FULL_REPORT_17Sep2025_1045UTC.md
            📝 Key findings are written to MWAA_DIAGNOSTICS_KEY_FINDINGS_17Sep2025_1045UTC.md
        """
        if self.full_report_requested:
            self.full_report_file.close()
            print("📝 Full report is written to", self.full_report_path)
        if self.key_findings_requested:
            self.key_findings_file.close()
            print("📝 Key findings are written to", self.key_findings_path)

