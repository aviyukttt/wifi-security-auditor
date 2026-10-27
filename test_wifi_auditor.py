import unittest
from wifi_core import password_findings


class PasswordFindingsTests(unittest.TestCase):
    def test_short_password_is_weak(self):
        label, findings = password_findings("abc")
        self.assertEqual(label, "Weak")
        self.assertTrue(any("12 characters" in item for item in findings))

    def test_long_varied_password_is_strong(self):
        label, findings = password_findings("Violet-River-93!Cloud")
        self.assertEqual(label, "Strong")
        self.assertTrue(findings)

    def test_common_word_is_flagged(self):
        label, findings = password_findings("Welcome123456789!")
        self.assertIn(label, {"Weak", "Moderate"})
        self.assertTrue(any("common" in item for item in findings))


if __name__ == "__main__":
    unittest.main()
