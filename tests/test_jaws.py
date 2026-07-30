import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from jaws.decoder import decode_token, is_token_valid_structure
from jaws.auditor import JWTAuditor
from jaws.cracker import HMACCracker
from jaws.models import Severity, DecodedToken


class TestDecoder:
    def test_valid_jwt_structure(self):
        token = "header.payload.signature"
        assert is_token_valid_structure(token) is True

    def test_two_part_token_is_valid(self):
        # alg=none allows empty signature
        token = "header.payload"
        assert is_token_valid_structure(token) is True

    def test_invalid_token_format(self):
        token = "header"
        assert is_token_valid_structure(token) is False

    def test_decode_token_valid(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        header, payload, signature = decode_token(token)
        assert header is not None
        assert payload is not None
        assert signature is not None
        assert header.get('alg') == 'HS256'

    def test_alg_none_detection(self):
        token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyfQ."
        header, payload, signature = decode_token(token)
        assert header is not None
        assert header.get('alg') == 'none'


class TestAuditor:
    def test_alg_none_finding(self):
        token = DecodedToken(
            raw="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            header={'alg': 'none', 'typ': 'JWT'},
            payload={'sub': 'test', 'iat': 1516239022},
            signature=""
        )
        auditor = JWTAuditor()
        findings = auditor.audit(token)
        assert any(f.severity == Severity.CRITICAL and "alg=none" in f.title for f in findings)

    def test_missing_exp_finding(self):
        token = DecodedToken(
            raw="header.payload.signature",
            header={'alg': 'HS256'},
            payload={'sub': 'test'},
            signature="sig"
        )
        auditor = JWTAuditor()
        findings = auditor.audit(token)
        assert any(f.severity == Severity.HIGH and "exp" in f.field for f in findings)

    def test_symmetric_alg_finding(self):
        token = DecodedToken(
            raw="header.payload.signature",
            header={'alg': 'HS256'},
            payload={'sub': 'test', 'exp': 9999999999},
            signature="sig"
        )
        auditor = JWTAuditor()
        findings = auditor.audit(token)
        assert any(f.severity == Severity.MEDIUM and "Symmetric" in f.title for f in findings)


class TestCracker:
    def test_hmac_crack_with_known_secret(self):
        raw_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        token = DecodedToken(
            raw=raw_token,
            header={'alg': 'HS256', 'typ': 'JWT'},
            payload={'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022},
            signature="SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        cracker = HMACCracker(token, timeout=5)
        # The secret that actually signs this token (verified by custom wordlist test)
        wordlist = ["your-256-bit-secret"]
        result = cracker.crack(wordlist)
        assert result == "your-256-bit-secret"

    def test_hmac_crack_no_match(self):
        raw_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        token = DecodedToken(
            raw=raw_token,
            header={'alg': 'HS256', 'typ': 'JWT'},
            payload={'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022},
            signature="SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        cracker = HMACCracker(token, timeout=5)
        wordlist = ["wrong1", "wrong2", "wrong3"]
        result = cracker.crack(wordlist)
        assert result is None
