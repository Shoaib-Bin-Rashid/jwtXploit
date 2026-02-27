"""
Unit tests for jwtXploit.py
Run with:  python3 -m pytest tests/  (or python3 -m unittest discover tests/)
"""
import base64
import json
import os
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import MagicMock, patch

# ── Load module without executing main() ─────────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.argv = ["jwtXploit.py", "placeholder"]          # satisfy argparse in module scope

_SRC = open(os.path.join(_ROOT, "jwtXploit.py"), encoding="utf-8").read()
_MOD = types.ModuleType("jwtxploit")
_MOD.__file__ = os.path.join(_ROOT, "jwtXploit.py")
exec(compile(_SRC.split("if __name__")[0], "jwtXploit.py", "exec"), _MOD.__dict__)

# Shortcuts
decode_token        = _MOD.decode_token
get_header          = _MOD.get_header
apply_exp_strip     = _MOD.apply_exp_strip
manual_none_token   = _MOD.manual_none_token
scan_token_secrets  = _MOD.scan_token_secrets
recommend_attacks   = _MOD.recommend_attacks
save_report         = _MOD.save_report
_cve_for_attack     = _MOD._cve_for_attack
_parse_batch_line   = _MOD._parse_batch_line
fingerprint_jwt_library = _MOD.fingerprint_jwt_library
CONFIG              = _MOD.CONFIG

# A real HS256 token with a known payload for testing
_TEST_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciIsImV4cCI6OTk5OTk5OTk5OX0"
    ".junk_sig"
)
# RS256 token (no valid sig needed — we only decode header/payload)
_RS256_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0xIn0"
    ".eyJzdWIiOiI3IiwicGF5Z3JhZGUiOiJhZG1pbiJ9"
    ".sig"
)


# ─────────────────────────────────────────────────────────────────────────────
class TestDecodeToken(unittest.TestCase):

    def test_decodes_payload(self):
        p = decode_token(_TEST_TOKEN)
        self.assertEqual(p["sub"], "123")
        self.assertEqual(p["role"], "user")

    def test_decodes_header(self):
        h = get_header(_TEST_TOKEN)
        self.assertEqual(h["alg"], "HS256")
        self.assertEqual(h["typ"], "JWT")

    def test_rs256_header(self):
        h = get_header(_RS256_TOKEN)
        self.assertEqual(h["alg"], "RS256")
        self.assertEqual(h["kid"], "key-1")


# ─────────────────────────────────────────────────────────────────────────────
class TestApplyExpStrip(unittest.TestCase):

    def setUp(self):
        CONFIG["strip_exp"] = True

    def tearDown(self):
        CONFIG["strip_exp"] = False

    def test_removes_nbf_and_iat(self):
        payload = {"sub": "1", "nbf": 1000, "iat": 2000, "exp": 3000}
        result  = apply_exp_strip(payload)
        self.assertNotIn("nbf", result)
        self.assertNotIn("iat", result)

    def test_sets_exp_far_future(self):
        payload = {"sub": "1", "exp": 1000}
        result  = apply_exp_strip(payload)
        self.assertGreater(result["exp"], int(time.time()) + 300_000_000)

    def test_noop_when_disabled(self):
        CONFIG["strip_exp"] = False
        payload = {"sub": "1", "nbf": 1000, "iat": 2000}
        result  = apply_exp_strip(payload)
        self.assertIn("nbf", result)
        self.assertIn("iat", result)


# ─────────────────────────────────────────────────────────────────────────────
class TestManualNoneToken(unittest.TestCase):

    def _parts(self, tok):
        return tok.split(".")

    def test_three_parts(self):
        tok = manual_none_token({"alg": "none"}, {"sub": "1"})
        self.assertEqual(len(self._parts(tok)), 3)

    def test_empty_signature(self):
        tok = manual_none_token({"alg": "None"}, {"sub": "1"})
        self.assertEqual(self._parts(tok)[2], "")

    def test_alg_preserved_in_header(self):
        for variant in ("none", "None", "NONE", "nOnE"):
            tok = manual_none_token({"alg": variant}, {"sub": "1"})
            hdr_b64 = self._parts(tok)[0]
            padding = 4 - len(hdr_b64) % 4
            hdr     = json.loads(base64.urlsafe_b64decode(hdr_b64 + "=" * padding))
            self.assertEqual(hdr["alg"], variant)

    def test_payload_round_trip(self):
        payload = {"sub": "42", "role": "admin"}
        tok     = manual_none_token({"alg": "none"}, payload)
        pay_b64 = self._parts(tok)[1]
        padding = 4 - len(pay_b64) % 4
        decoded = json.loads(base64.urlsafe_b64decode(pay_b64 + "=" * padding))
        self.assertEqual(decoded["sub"], "42")
        self.assertEqual(decoded["role"], "admin")


# ─────────────────────────────────────────────────────────────────────────────
class TestScanTokenSecrets(unittest.TestCase):

    def test_detects_aws_key_in_payload(self):
        """Payload containing an AWS-like key should trigger a warning (no crash)."""
        payload_dict = {"sub": "1", "secret": "AKIAIOSFODNN7EXAMPLE"}
        payload_b64  = base64.urlsafe_b64encode(
            json.dumps(payload_dict).encode()
        ).rstrip(b"=").decode()
        fake_token   = f"eyJhbGciOiJIUzI1NiJ9.{payload_b64}.sig"
        # Should not raise
        scan_token_secrets(fake_token)

    def test_clean_token_no_crash(self):
        scan_token_secrets(_TEST_TOKEN)


# ─────────────────────────────────────────────────────────────────────────────
class TestRecommendAttacks(unittest.TestCase):

    def _get_tips(self, header, payload):
        """Capture printed output from recommend_attacks."""
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            recommend_attacks(header, payload)
        return buf.getvalue()

    def test_rs256_suggests_confusion(self):
        out = self._get_tips({"alg": "RS256"}, {})
        self.assertIn("Algorithm Confusion", out)

    def test_es256_suggests_psychic(self):
        out = self._get_tips({"alg": "ES256"}, {})
        self.assertIn("Psychic Signature", out)

    def test_kid_suggests_traversal_sqli_ssrf(self):
        out = self._get_tips({"alg": "HS256", "kid": "key-1"}, {})
        self.assertIn("KID Path Traversal", out)
        self.assertIn("KID SQL Injection", out)
        self.assertIn("KID SSRF", out)

    def test_hs256_suggests_brute_force(self):
        out = self._get_tips({"alg": "HS256"}, {})
        self.assertIn("Weak Key Brute Force", out)

    def test_x5c_suggests_injection(self):
        out = self._get_tips({"alg": "RS256", "x5c": ["abc"]}, {})
        self.assertIn("x5c Header Injection", out)

    def test_expired_token_info(self):
        out = self._get_tips({"alg": "HS256"}, {"exp": 1000})
        self.assertIn("strip-exp", out)

    def test_no_exp_info(self):
        out = self._get_tips({"alg": "HS256"}, {})
        self.assertIn("No exp claim", out)


# ─────────────────────────────────────────────────────────────────────────────
class TestCveLookup(unittest.TestCase):

    def test_alg_none(self):
        cve_id, cvss, _ = _cve_for_attack("alg:none bypass")
        self.assertEqual(cve_id, "CVE-2015-9235")
        self.assertEqual(cvss, "9.8")

    def test_jwk_injection(self):
        cve_id, *_ = _cve_for_attack("JWK Header Injection")
        self.assertEqual(cve_id, "CVE-2018-0114")

    def test_psychic_signature(self):
        cve_id, *_ = _cve_for_attack("ES256 Psychic Signature Bypass (CVE-2022-21449)")
        self.assertEqual(cve_id, "CVE-2022-21449")

    def test_x5c(self):
        cve_id, *_ = _cve_for_attack("x5c Header Injection")
        self.assertEqual(cve_id, "CVE-2018-0114")

    def test_kid_sql(self):
        result = _cve_for_attack("KID SQL Injection")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "N/A")  # no assigned CVE but rated 9.1

    def test_unknown_returns_none(self):
        self.assertIsNone(_cve_for_attack("something totally unknown"))


# ─────────────────────────────────────────────────────────────────────────────
class TestSaveReport(unittest.TestCase):

    def setUp(self):
        CONFIG["findings"] = [
            {
                "attack":        "alg:none",
                "token":         "hdr.pay.",
                "payload":       {"sub": "1", "role": "admin"},
                "header":        {"alg": "none"},
                "verified":      True,
                "verify_reason": "Status code changed: 403 → 200",
                "delivery":      "Authorization: Bearer",
                "timestamp":     "2026-01-01T00:00:00Z",
            },
            {
                "attack":        "KID SQL Injection",
                "token":         "x.y.z",
                "payload":       {"sub": "1"},
                "header":        {"kid": "' UNION SELECT 'x'-- -"},
                "verified":      False,
                "verify_reason": None,
                "delivery":      None,
                "timestamp":     "2026-01-01T00:01:00Z",
            },
        ]

    def tearDown(self):
        CONFIG["findings"] = []

    def _save_and_read(self, fmt):
        with tempfile.NamedTemporaryFile(suffix=f".{fmt}", delete=False) as f:
            path = f.name
        try:
            save_report(path, fmt)
            with open(path, encoding="utf-8") as f:
                return f.read()
        finally:
            os.unlink(path)

    def test_json_is_valid(self):
        content = self._save_and_read("json")
        data    = json.loads(content)
        self.assertEqual(data["stats"]["total_generated"], 2)
        self.assertEqual(data["stats"]["confirmed_accepted"], 1)
        self.assertEqual(data["findings"][0]["attack"], "alg:none")

    def test_txt_contains_accepted(self):
        content = self._save_and_read("txt")
        self.assertIn("ACCEPTED", content)
        self.assertIn("alg:none", content)

    def test_md_contains_cve(self):
        content = self._save_and_read("md")
        self.assertIn("CVE-2015-9235", content)
        self.assertIn("## Confirmed Findings", content)

    def test_empty_findings_no_crash(self):
        CONFIG["findings"] = []
        # Should print warning and return without error
        save_report("/tmp/empty_test.json", "json")


# ─────────────────────────────────────────────────────────────────────────────
class TestParseBatchLine(unittest.TestCase):

    def test_token_only(self):
        tok, url = _parse_batch_line("eyJhbGciOiJIUzI1NiJ9.payload.sig")
        self.assertEqual(tok, "eyJhbGciOiJIUzI1NiJ9.payload.sig")
        self.assertIsNone(url)

    def test_token_double_colon_url(self):
        tok, url = _parse_batch_line("mytoken::https://example.com/api")
        self.assertEqual(tok, "mytoken")
        self.assertEqual(url, "https://example.com/api")

    def test_token_space_url(self):
        tok, url = _parse_batch_line("mytoken https://example.com/api")
        self.assertEqual(tok, "mytoken")
        self.assertEqual(url, "https://example.com/api")

    def test_comment_line_returns_none(self):
        self.assertIsNone(_parse_batch_line("# this is a comment"))

    def test_blank_line_returns_none(self):
        self.assertIsNone(_parse_batch_line(""))
        self.assertIsNone(_parse_batch_line("   "))

    def test_strips_whitespace(self):
        tok, url = _parse_batch_line("  mytoken::https://example.com  ")
        self.assertEqual(tok, "mytoken")
        self.assertEqual(url, "https://example.com")


# ─────────────────────────────────────────────────────────────────────────────
class TestFingerprintHeaderMatching(unittest.TestCase):
    """Test the response-header-based fingerprinting path without network calls."""

    def test_express_header_matches_jsonwebtoken(self):
        """X-Powered-By: Express should identify jsonwebtoken."""
        mock_resp = MagicMock()
        mock_resp.headers = {"X-Powered-By": "Express", "Content-Type": "application/json"}
        mock_resp.text = ""
        mock_resp.status_code = 401

        with patch("requests.Session.get", return_value=mock_resp):
            CONFIG["proxy"]      = None
            CONFIG["ssl_verify"] = True
            CONFIG["timeout"]    = 5
            CONFIG["findings"]   = []
            fingerprint_jwt_library("dummy.token.here", url="http://fake-target.local")

        confirmed = [f for f in CONFIG["findings"] if f.get("verified")]
        self.assertTrue(
            any("jsonwebtoken" in f.get("verify_reason", "") for f in confirmed),
            msg=f"Expected jsonwebtoken fingerprint. Findings: {CONFIG['findings']}"
        )

    def test_php_header_matches_firebase(self):
        """X-Powered-By: PHP should identify firebase/php-jwt."""
        mock_resp = MagicMock()
        mock_resp.headers = {"X-Powered-By": "PHP/8.1.0"}
        mock_resp.text = ""
        mock_resp.status_code = 401

        with patch("requests.Session.get", return_value=mock_resp):
            CONFIG["findings"] = []
            fingerprint_jwt_library("dummy.token.here", url="http://fake-target.local")

        confirmed = [f for f in CONFIG["findings"] if f.get("verified")]
        self.assertTrue(
            any("php" in f.get("verify_reason", "").lower() for f in confirmed),
            msg=f"Expected PHP/firebase fingerprint. Findings: {CONFIG['findings']}"
        )

    def test_no_header_no_body_does_not_crash(self):
        """Fingerprint should complete without crashing when no hints are found."""
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.text    = "No error details here"
        mock_resp.status_code = 401

        with patch("requests.Session.get", return_value=mock_resp):
            CONFIG["findings"] = []
            fingerprint_jwt_library("dummy.token.here", url="http://fake-target.local")
        # No assertion needed — just must not raise


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    unittest.main(verbosity=2)
