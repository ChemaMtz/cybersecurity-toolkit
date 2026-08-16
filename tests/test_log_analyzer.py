"""
Unit tests for LogAnalyzer module.
"""

import sys
import os
import unittest
import tempfile

# Asegurar importación de herramientas
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.forensics.log_analyzer import LogAnalyzer, SecurityAlert, LogAuditReport


class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = LogAnalyzer(brute_force_threshold=3)
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_detect_sqli_in_web_log(self):
        log_content = (
            '192.168.1.50 - - [10/Aug/2026:14:32:10 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 4520\n'
        )
        logfile_path = os.path.join(self.temp_dir.name, "sqli_test.log")
        with open(logfile_path, "w", encoding="utf-8") as f:
            f.write(log_content)

        report = self.analyzer.analyze_web_log(logfile_path)
        self.assertEqual(report.total_lines, 1)
        self.assertEqual(report.total_alerts, 1)
        self.assertIn("SQL Injection (SQLi)", report.alerts_by_type)
        self.assertEqual(report.alerts[0].ip, "192.168.1.50")
        self.assertEqual(report.alerts[0].severity, "HIGH")

    def test_detect_xss_in_web_log(self):
        log_content = (
            '10.0.0.15 - - [10/Aug/2026:14:35:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1200\n'
        )
        logfile_path = os.path.join(self.temp_dir.name, "xss_test.log")
        with open(logfile_path, "w", encoding="utf-8") as f:
            f.write(log_content)

        report = self.analyzer.analyze_web_log(logfile_path)
        self.assertEqual(report.total_alerts, 1)
        self.assertIn("Cross-Site Scripting (XSS)", report.alerts_by_type)

    def test_detect_directory_traversal(self):
        log_content = (
            '172.16.0.4 - - [10/Aug/2026:14:40:00 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 404 320\n'
        )
        logfile_path = os.path.join(self.temp_dir.name, "traversal_test.log")
        with open(logfile_path, "w", encoding="utf-8") as f:
            f.write(log_content)

        report = self.analyzer.analyze_web_log(logfile_path)
        self.assertEqual(report.total_alerts, 1)
        self.assertIn("Directory Traversal / LFI", report.alerts_by_type)
        self.assertEqual(report.alerts[0].severity, "CRITICAL")

    def test_detect_brute_force_threshold(self):
        log_content = "\n".join([
            f'192.168.1.100 - - [10/Aug/2026:15:00:0{i} +0000] "POST /api/login HTTP/1.1" 401 120'
            for i in range(4)
        ]) + "\n"
        logfile_path = os.path.join(self.temp_dir.name, "brute_test.log")
        with open(logfile_path, "w", encoding="utf-8") as f:
            f.write(log_content)

        report = self.analyzer.analyze_web_log(logfile_path)
        self.assertTrue(any(a.attack_type == "Brute Force" for a in report.alerts))
        self.assertEqual(report.status_code_distribution.get("401"), 4)


if __name__ == "__main__":
    unittest.main()
