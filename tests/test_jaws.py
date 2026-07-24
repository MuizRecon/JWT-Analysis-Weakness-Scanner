import base64
import json
import os
import sys
import time

import jwt
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jaws import parse_jwt, generate_findings, attempt_hmac_crack


class TestJWTScanner:
    def test_valid_token_parses(self):
        token = jwt.encode({"user": "test", "exp": int(time.time()) + 60}, "secret", algorithm="HS256")
        decoded = parse_jwt(token)
        assert decoded.header.get("alg") == "HS256"
        assert "user" in decoded.payload

    def test_alg_none_detected(self):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"user": "admin"}).encode()).decode().rstrip("=")
        token = f"{header}.{payload}."
        decoded = parse_jwt(token)
        findings = generate_findings(decoded)
        assert any("none" in f.title.lower() for f in findings)

    def test_missing_exp_detected(self):
        token = jwt.encode({"user": "test"}, "secret", algorithm="HS256")
        decoded = parse_jwt(token)
        findings = generate_findings(decoded)
        assert any("exp" in f.title.lower() for f in findings)

    def test_expired_token_detected(self):
        token = jwt.encode({"user": "test", "exp": int(time.time()) - 60}, "secret", algorithm="HS256")
        decoded = parse_jwt(token)
        findings = generate_findings(decoded)
        assert any("expired" in f.title.lower() for f in findings)

    def test_kid_header_detected(self):
        token = jwt.encode(
            {"user": "test", "exp": int(time.time()) + 60},
            "secret",
            algorithm="HS256",
            headers={"kid": "my-key"},
        )
        decoded = parse_jwt(token)
        findings = generate_findings(decoded)
        assert any("kid" in f.title.lower() for f in findings)

    def test_hmac_crack_finds_secret(self):
        token = jwt.encode({"user": "admin"}, "secret123", algorithm="HS256")
        decoded = parse_jwt(token)
        findings = []
        candidates = ["wrong", "secret123", "another"]
        cracked, tried = attempt_hmac_crack(decoded, (s for s in candidates), findings, use_color=False)
        assert cracked == "secret123"
        assert tried == 2

    def test_hmac_crack_rejects_wrong_secrets(self):
        token = jwt.encode({"user": "admin"}, "supersecret", algorithm="HS256")
        decoded = parse_jwt(token)
        findings = []
        candidates = ["wrong", "wrong2", "wrong3"]
        cracked, tried = attempt_hmac_crack(decoded, (s for s in candidates), findings, use_color=False)
        assert cracked is None
        assert tried == 3

    def test_invalid_token_rejected(self):
        with pytest.raises(ValueError):
            parse_jwt("not.a.jwt")

    def test_token_size_limit_enforced(self):
        huge_token = "a" * 20000
        with pytest.raises(ValueError):
            parse_jwt(huge_token)
