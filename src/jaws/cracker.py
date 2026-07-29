"""HMAC secret cracking for JWT tokens."""

import hmac
import hashlib
import time
from typing import Optional, Generator
from .models import DecodedToken


class HMACCracker:
    """Attempts to recover HMAC signing secrets via brute force."""

    def __init__(self, token: DecodedToken, timeout: int = 60):
        self.token = token
        self.timeout = timeout
        self._start_time: Optional[float] = None

    def _get_signature_parts(self) -> Optional[tuple]:
        """Extract the signing input and signature from the token."""
        parts = self.token.raw.split('.')
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}"
        signature = parts[2]
        return signing_input, signature

    def _test_secret(self, secret: str, signing_input: str, signature: str,
                     alg: str = 'HS256') -> bool:
        """Test if a secret produces the correct signature."""
        try:
            algo_map = {
                'HS256': hashlib.sha256,
                'HS384': hashlib.sha384,
                'HS512': hashlib.sha512,
            }
            hash_func = algo_map.get(alg, hashlib.sha256)
            computed = hmac.new(
                secret.encode('utf-8'),
                signing_input.encode('utf-8'),
                hash_func
            ).digest()
            return hmac.compare_digest(
                computed.hex(),
                signature
            )
        except Exception:
            return False

    def crack(self, wordlist: Generator[str, None, None]) -> Optional[str]:
        """
        Attempt to crack the HMAC secret using a wordlist.

        Returns:
            The recovered secret, or None if not found.
        """
        self._start_time = time.time()
        parts = self._get_signature_parts()
        if not parts:
            return None

        signing_input, signature = parts
        alg = self.token.header.get('alg', 'HS256')

        for word in wordlist:
            if time.time() - self._start_time > self.timeout:
                break
            if self._test_secret(word, signing_input, signature, alg):
                return word

        return None
