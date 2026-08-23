import unittest

from scanner.risk_engine import calculate_risk, severity_band, sort_key


class TestCalculateRisk(unittest.TestCase):
    def test_maximum_score(self):
        self.assertEqual(calculate_risk(5, 5, 5), 10.0)

    def test_minimum_score(self):
        self.assertEqual(calculate_risk(1, 1, 1), 0.1)

    def test_known_bola_score(self):
        # likelihood 5, impact 5, exposure 4 -> 100/125 * 10
        self.assertEqual(calculate_risk(5, 5, 4), 8.0)

    def test_exposure_dominates(self):
        """A severe but admin-only issue must score below a mild anonymous one."""
        admin_only_severe = calculate_risk(5, 5, 2)
        anonymous_mild = calculate_risk(5, 3, 5)
        self.assertLess(admin_only_severe, anonymous_mild)

    def test_rejects_out_of_range(self):
        for bad in (0, 6, -1):
            with self.assertRaises(ValueError):
                calculate_risk(bad, 3, 3)

    def test_error_names_the_offending_axis(self):
        with self.assertRaises(ValueError) as ctx:
            calculate_risk(3, 9, 3)
        self.assertIn("impact", str(ctx.exception))


class TestSeverityBand(unittest.TestCase):
    def test_bands(self):
        cases = [
            (10.0, "CRITICAL"),
            (9.0, "CRITICAL"),
            (8.9, "HIGH"),
            (7.0, "HIGH"),
            (6.9, "MEDIUM"),
            (4.0, "MEDIUM"),
            (3.9, "LOW"),
            (0.1, "LOW"),
        ]
        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(severity_band(score), expected)


class TestSortKey(unittest.TestCase):
    def test_orders_critical_first_then_by_score(self):
        findings = [
            {"id": "APC-003", "severity": "LOW", "risk_score": 2.4},
            {"id": "APC-001", "severity": "CRITICAL", "risk_score": 10.0},
            {"id": "APC-002", "severity": "HIGH", "risk_score": 8.0},
        ]
        ordered = [f["id"] for f in sorted(findings, key=sort_key)]
        self.assertEqual(ordered, ["APC-001", "APC-002", "APC-003"])

    def test_ties_break_on_id(self):
        findings = [
            {"id": "APC-009", "severity": "HIGH", "risk_score": 8.0},
            {"id": "APC-002", "severity": "HIGH", "risk_score": 8.0},
        ]
        ordered = [f["id"] for f in sorted(findings, key=sort_key)]
        self.assertEqual(ordered, ["APC-002", "APC-009"])


if __name__ == "__main__":
    unittest.main()
