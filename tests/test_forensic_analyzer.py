"""
Unit tests for ForensicAnalyzer module.
"""

import sys
import os
import unittest
import tempfile

# Ensure toolkit root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.forensics.forensic_analyzer import ForensicAnalyzer, ForensicArtifact


class TestForensicAnalyzer(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.analyzer = ForensicAnalyzer(evidence_dir=self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_collect_system_info(self):
        sys_info = self.analyzer.collect_system_info()
        self.assertIn("system", sys_info)
        self.assertIn("os", sys_info["system"])
        self.assertIn("hostname", sys_info["system"])

    def test_analyze_custom_log_dir(self):
        # Create a log with suspicious pattern
        log_file = os.path.join(self.temp_dir.name, "auth.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("Aug 15 12:00:01 server sshd[1234]: Failed password for root from 192.168.1.50\n")

        artifacts = self.analyzer.analyze_logs(log_dir=self.temp_dir.name)
        self.assertTrue(any(a.type == "Authentication Failure" for a in artifacts))

    def test_generate_report(self):
        report_path = os.path.join(self.temp_dir.name, "test_report.json")
        report = self.analyzer.generate_report(output_file=report_path)
        self.assertTrue(os.path.exists(report_path))
        self.assertIn("statistics", report)
        self.assertIn("total_artifacts", report["statistics"])


if __name__ == "__main__":
    unittest.main()
