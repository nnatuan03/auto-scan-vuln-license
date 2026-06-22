import unittest

from autoscan.license_relation import classify_license_relation


class LicenseRelationTests(unittest.TestCase):
    def test_spdx_or_expression_allows_choice(self):
        result = classify_license_relation(["MIT OR Apache-2.0"])
        self.assertEqual(result["relation"], "OR")
        self.assertIn("choose", result["requirement"].lower())

    def test_spdx_and_expression_requires_all(self):
        result = classify_license_relation(["MIT AND BSD-3-Clause"])
        self.assertEqual(result["relation"], "AND")
        self.assertIn("all", result["requirement"].lower())

    def test_multiple_separate_licenses_need_manual_review(self):
        result = classify_license_relation(["MIT", "Apache-2.0"])
        self.assertEqual(result["relation"], "REVIEW")

    def test_non_spdx_or_unknown_need_manual_review(self):
        self.assertEqual(classify_license_relation(["LicenseRef-No-Declared-License"])["relation"], "REVIEW")
        self.assertEqual(classify_license_relation(["MIT OR custom license"])["relation"], "REVIEW")


if __name__ == "__main__":
    unittest.main()
