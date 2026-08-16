"""
Unit tests for PasswordAnalyzer module.
"""

import sys
import os
import unittest

# Asegurar importación de herramientas
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.security.password_analyzer import PasswordAnalyzer, PasswordReport


class TestPasswordAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = PasswordAnalyzer()

    def test_empty_password(self):
        entropy = self.analyzer.calculate_entropy("")
        self.assertEqual(entropy, 0.0)

    def test_entropy_increases_with_complexity(self):
        e1 = self.analyzer.calculate_entropy("aaaa")
        e2 = self.analyzer.calculate_entropy("aA1!")
        self.assertGreater(e2, e1)

    def test_common_weak_password_detection(self):
        report = self.analyzer.analyze("123456")
        self.assertTrue(report.is_common)
        self.assertEqual(report.strength, "MUY DÉBIL")
        self.assertLess(report.score, 30)
        self.assertTrue(any("vulneradas" in s for s in report.suggestions))

    def test_strong_complex_password(self):
        report = self.analyzer.analyze("C0mpl3x-P@ssw0rd!#2026")
        self.assertFalse(report.is_common)
        self.assertTrue(report.has_upper)
        self.assertTrue(report.has_lower)
        self.assertTrue(report.has_digit)
        self.assertTrue(report.has_special)
        self.assertGreaterEqual(report.score, 80)
        self.assertIn(report.strength, ["FUERTE", "MUY FUERTE"])
        self.assertGreater(report.entropy_bits, 60.0)

    def test_short_password_suggestions(self):
        report = self.analyzer.analyze("Ab1!")
        self.assertTrue(any("longitud" in s.lower() for s in report.suggestions))

    def test_masked_password(self):
        report = self.analyzer.analyze("secretword")
        self.assertEqual(report.password_masked, "s********d")


if __name__ == "__main__":
    unittest.main()
