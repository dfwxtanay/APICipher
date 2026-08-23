import os
import unittest

from scanner.scanner import parse_assertion_name, redact, build_finding, scan


class TestParseAssertionName(unittest.TestCase):
    def test_parses_four_segments(self):
        name = "APC-001 | BOLA | GET /users/{user_id} | Must deny cross-user access"
        self.assertEqual(
            parse_assertion_name(name),
            {
                "id": "APC-001",
                "vuln_type": "BOLA",
                "endpoint": "GET /users/{user_id}",
                "description": "Must deny cross-user access",
            },
        )

    def test_ignores_names_without_the_convention(self):
        self.assertIsNone(parse_assertion_name("Status code is 200"))
        self.assertIsNone(parse_assertion_name("APC-001 | BOLA"))


class TestRedact(unittest.TestCase):
    def test_strips_argon2_hash_but_keeps_field_name(self):
        body = '{"password":"$argon2id$v=19$m=65536,t=3,p=4$abc$def","id":1}'
        out = redact(body)
        self.assertNotIn("m=65536", out)
        self.assertIn('"password"', out)  # evidence of the leak survives
        self.assertIn("[REDACTED]", out)

    def test_strips_jwt(self):
        body = '{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo3fQ.sig-value"}'
        self.assertIn("[JWT_REDACTED]", redact(body))

    def test_leaves_ordinary_text_alone(self):
        body = '{"description":"user_b CONFIDENTIAL salary"}'
        self.assertEqual(redact(body), body)


class TestBuildFinding(unittest.TestCase):
    def _execution(self):
        return {
            "request": {
                "method": "GET",
                "url": {"protocol": "http", "host": ["127", "0", "0", "1"],
                        "port": "8000", "path": ["users", "8"]},
            },
            "response": {"code": 200, "stream": {"type": "Buffer", "data": list(b'{"id":8}')}},
        }

    def test_applies_exposure_override(self):
        meta = {"id": "APC-011", "vuln_type": "DATA_EXPOSURE",
                "endpoint": "GET /admin/users", "description": "no hashes"}
        finding = build_finding(meta, self._execution(), "boom")
        # admin-only exposure of 2 pulls this down from the class default of 4
        self.assertEqual(finding["scoring"]["exposure"], 2)
        self.assertEqual(finding["severity"], "MEDIUM")

    def test_rebuilds_url_for_evidence(self):
        meta = {"id": "APC-001", "vuln_type": "BOLA",
                "endpoint": "GET /users/{user_id}", "description": "deny"}
        finding = build_finding(meta, self._execution(), "boom")
        self.assertEqual(finding["evidence"]["request"], "GET http://127.0.0.1:8000/users/8")
        self.assertEqual(finding["status"], "OPEN")


class TestScanIntegration(unittest.TestCase):
    """Runs against the committed Newman report so the parser stays honest."""

    def test_vulnerable_run_produces_expected_shape(self):
        if not os.path.exists("reports/newman-results.json"):
            self.skipTest("no Newman report present - run a scan first")

        result = scan("reports/newman-results.json")
        self.assertIn("findings", result)
        self.assertEqual(
            result["summary"]["assertions_total"],
            len(result["findings"]) + result["summary"]["tests_passed"],
        )
        for finding in result["findings"]:
            self.assertTrue(finding["id"].startswith("APC-"))
            self.assertIn(finding["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
            self.assertTrue(0 < finding["risk_score"] <= 10)
            self.assertTrue(finding["remediation"])


if __name__ == "__main__":
    unittest.main()
