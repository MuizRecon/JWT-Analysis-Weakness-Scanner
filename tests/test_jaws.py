import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from jaws import cli
from jaws.auditor import JWTAuditor
from jaws.cracker import HMACCracker
from jaws.decoder import decode_token, is_token_valid_structure
from jaws.models import DecodedToken, Severity


class TestDecoder:
    def test_valid_jwt_structure(self):
        token = "header.payload.signature"
        assert is_token_valid_structure(token) is True

    def test_alg_none_empty_signature_is_valid(self):
        token = "header.payload."
        assert is_token_valid_structure(token) is True

    def test_two_part_token_is_invalid(self):
        token = "header.payload"
        assert is_token_valid_structure(token) is False

    def test_invalid_token_format(self):
        token = "header"
        assert is_token_valid_structure(token) is False

    def test_decode_token_valid(self):
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )

        header, payload, signature = decode_token(token)

        assert header is not None
        assert payload is not None
        assert signature is not None
        assert header.get("alg") == "HS256"

    def test_alg_none_detection(self):
        token = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyfQ."
        )

        header, payload, signature = decode_token(token)

        assert header is not None
        assert header.get("alg") == "none"


class TestAuditor:
    def test_alg_none_finding(self):
        token = DecodedToken(
            raw="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            header={"alg": "none", "typ": "JWT"},
            payload={"sub": "test", "iat": 1516239022},
            signature="",
        )

        findings = JWTAuditor().audit(token)

        assert any(
            finding.severity == Severity.CRITICAL and "alg=none" in finding.title
            for finding in findings
        )

    def test_missing_exp_finding(self):
        token = DecodedToken(
            raw="header.payload.signature",
            header={"alg": "HS256"},
            payload={"sub": "test"},
            signature="sig",
        )

        findings = JWTAuditor().audit(token)

        assert any(
            finding.severity == Severity.HIGH and "exp" in finding.field
            for finding in findings
        )

    def test_symmetric_alg_finding(self):
        token = DecodedToken(
            raw="header.payload.signature",
            header={"alg": "HS256"},
            payload={"sub": "test", "exp": 9999999999},
            signature="sig",
        )

        findings = JWTAuditor().audit(token)

        assert any(
            finding.severity == Severity.MEDIUM and "Symmetric" in finding.title
            for finding in findings
        )


class TestCracker:
    def test_hmac_crack_with_known_secret(self):
        raw_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )

        token = DecodedToken(
            raw=raw_token,
            header={"alg": "HS256", "typ": "JWT"},
            payload={"sub": "1234567890", "name": "John Doe", "iat": 1516239022},
            signature="SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )

        cracker = HMACCracker(token, timeout=5)
        result = cracker.crack(["your-256-bit-secret"])

        assert result == "your-256-bit-secret"

    def test_hmac_crack_no_match(self):
        raw_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )

        token = DecodedToken(
            raw=raw_token,
            header={"alg": "HS256", "typ": "JWT"},
            payload={"sub": "1234567890", "name": "John Doe", "iat": 1516239022},
            signature="SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )

        cracker = HMACCracker(token, timeout=5)
        result = cracker.crack(["wrong1", "wrong2", "wrong3"])

        assert result is None


class TestCLI:
    def test_cracked_secret_is_reported_as_critical_finding(
        self, monkeypatch, capsys
    ):
        raw_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJ1c2VybmFtZSI6ImFkbWluIn0."
            "qQSekbR5BFKQPc3_7gUiDY6Q9y7RojKzvBTLJ9jGtec"
        )

        monkeypatch.setattr(
            "sys.argv",
            ["jaws", raw_token, "--no-color", "--wordlist", "-"],
        )

        def fake_load_wordlist(path):
            return ["secret"]

        monkeypatch.setattr(cli, "load_wordlist", fake_load_wordlist)

        cli.main()
        output = capsys.readouterr().out

        assert "Secret recovered: secret" in output
        assert "Weak HMAC secret cracked" in output
        assert "'CRITICAL': 1" in output

    def test_two_part_token_does_not_crash(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["jaws", "abc.def"])

        exit_code = cli.main()
        error = capsys.readouterr().err

        assert exit_code == 1
        assert "Invalid JWT format" in error
