#!/usr/bin/env python3
"""
J.A.W.S. — JWT Analysis & Weakness Scanner
--------------------------------------------
A recon tool for bug bounty / API security testing.

Decodes a JWT, inspects its header and payload for common
misconfigurations, and (optionally) attempts to crack the
signing secret against a wordlist if the algorithm is HMAC-based.

No external dependencies — uses only the standard library, so it
runs anywhere without pip installs (useful on a fresh Kali box or
inside a restricted environment).

Usage:
    python jaws.py <token>
    python jaws.py <token> --wordlist secrets.txt
    python jaws.py --file token.txt --wordlist secrets.txt
    python jaws.py <token> --no-color     # plain output, e.g. for piping/logging
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Generator, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_JWT_FILE_SIZE = 10 * 1024  # 10 KB - JWTs are small
MAX_WORDLIST_SIZE = 50 * 1024 * 1024  # 50 MB - sane default
SPINNER_UPDATE_INTERVAL = 0.2  # seconds between spinner updates
DEFAULT_CRACK_TIMEOUT = 60  # seconds before giving up on cracking

# Small built-in list of common/default JWT secrets seen in the wild.
# Real assessments should supply a much larger wordlist (e.g. the
# "jwt-secrets" list from SecLists) via --wordlist.
DEFAULT_WEAK_SECRETS: Tuple[str, ...] = (
    "secret", "password", "123456", "your-256-bit-secret", "jwt_secret",
    "changeme", "supersecret", "secretkey", "key", "test", "admin",
    "qwerty", "letmein", "jwtsecret", "mysecretkey", "12345678",
    "", "null", "none", "default", "s3cr3t",
)

HMAC_ALGS: Dict[str, Any] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

SEVERITY_COLOR: Dict[str, str] = {
    "CRITICAL": "\033[1;97;41m",   # bold white on red
    "HIGH": "\033[1;31m",           # bold red
    "MEDIUM": "\033[1;33m",         # bold yellow
    "LOW": "\033[1;34m",            # bold blue
    "INFO": "\033[1;90m",           # bold gray
}

COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"
COLOR_CYAN = "\033[1;36m"
COLOR_MAGENTA = "\033[1;35m"
COLOR_GREEN = "\033[1;32m"

JAWS_BANNER = r"""
        _   ___        __/^\/^\/^\_______
       | | / \ \      /  ^          ^   \_
    _  | |/ A \ \    | J.A.W.S.           |
   | |_/ / W \_\_\    \___  ______________/
   |  _/ /  S  \_\        \/
   |_|/__/     \__\  JWT Analysis & Weakness Scanner
"""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Finding:
    """A single security finding from JWT analysis."""
    severity: str
    title: str
    detail: str
    recommendation: str


@dataclass(slots=True)
class DecodedJWT:
    """Container for a decoded JWT and its components."""
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    header_b64: str
    payload_b64: str
    signature_b64: str


# ---------------------------------------------------------------------------
# Terminal UI Helpers
# ---------------------------------------------------------------------------

def colorize(text: str, color: str, use_color: bool = True) -> str:
    """Wrap text in color codes if color output is enabled."""
    if not use_color:
        return text
    return f"{color}{text}{COLOR_RESET}"


def print_banner(use_color: bool = True) -> None:
    """Print the J.A.W.S. shark banner."""
    print(colorize(JAWS_BANNER, COLOR_CYAN, use_color))
    print(colorize("  Decode. Detect. Devour weak tokens.", COLOR_DIM, use_color))
    print()


def section_header(title: str, use_color: bool = True) -> None:
    """Print a formatted section header."""
    line = "─" * 70
    print(colorize(line, COLOR_DIM, use_color))
    print(colorize(f" {title}", COLOR_BOLD + COLOR_CYAN, use_color))
    print(colorize(line, COLOR_DIM, use_color))


def risk_verdict(findings: List[Finding], use_color: bool = True) -> str:
    """Generate a single top-line verdict."""
    if any(f.severity == "CRITICAL" for f in findings):
        return colorize(" 🦈  CRITICAL EXPOSURE — this token is forgeable/bypassable", 
                        SEVERITY_COLOR["CRITICAL"], use_color)
    if any(f.severity in ("HIGH", "MEDIUM") for f in findings):
        return colorize(" ⚠  WEAKNESSES FOUND — review findings below", 
                        SEVERITY_COLOR["MEDIUM"], use_color)
    if findings:
        return colorize(" ✓  No major issues — only minor/informational findings", 
                        SEVERITY_COLOR["LOW"], use_color)
    return colorize(" ✓  Clean — no issues flagged by automated checks", COLOR_GREEN, use_color)


class Spinner:
    """Simple terminal spinner with time-based updates."""
    
    def __init__(self, use_color: bool = True):
        self.use_color = use_color
        self.frames = "|/-\\"
        self.last_update = 0.0
        self.frame_index = 0
    
    def update(self, tried: int, label: str = "") -> None:
        """Update the spinner if enough time has passed."""
        if not self.use_color or not sys.stdout.isatty():
            return
        
        now = time.time()
        if now - self.last_update < SPINNER_UPDATE_INTERVAL:
            return
        
        self.last_update = now
        frame = self.frames[self.frame_index % len(self.frames)]
        self.frame_index += 1
        
        status = f"  {colorize(frame, COLOR_MAGENTA, self.use_color)} testing secrets... {tried} tried"
        if label:
            status += f" ({label})"
        
        sys.stdout.write(f"\r{status:<70}")
        sys.stdout.flush()
    
    def clear(self) -> None:
        """Clear the spinner line."""
        if not self.use_color or not sys.stdout.isatty():
            return
        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# JWT Parsing
# ---------------------------------------------------------------------------

def b64url_decode(segment: str) -> bytes:
    """Base64url-decode a JWT segment, padding as needed."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def parse_jwt(token: str) -> DecodedJWT:
    """Parse a JWT string into its components."""
    parts = token.strip().split(".")
    
    if len(parts) != 3:
        raise ValueError(
            f"Token has {len(parts)} segments, expected 3 (header.payload.signature). "
            "Is this actually a JWT?"
        )
    
    header_b64, payload_b64, signature_b64 = parts
    
    # Validate token size before decoding
    if len(token) > MAX_JWT_FILE_SIZE:
        raise ValueError(f"Token exceeds maximum size ({MAX_JWT_FILE_SIZE} bytes)")
    
    try:
        header = json.loads(b64url_decode(header_b64))
        if not isinstance(header, dict):
            raise ValueError("Header is not a JSON object")
    except (binascii.Error, json.JSONDecodeError) as e:
        raise ValueError(f"Could not decode/parse header: {e}")
    
    try:
        payload = json.loads(b64url_decode(payload_b64))
        if not isinstance(payload, dict):
            raise ValueError("Payload is not a JSON object")
    except (binascii.Error, json.JSONDecodeError) as e:
        raise ValueError(f"Could not decode/parse payload: {e}")
    
    try:
        signature = b64url_decode(signature_b64)
    except binascii.Error:
        signature = b""  # some servers accept malformed/empty sig
    
    return DecodedJWT(
        header=header,
        payload=payload,
        signature=signature,
        header_b64=header_b64,
        payload_b64=payload_b64,
        signature_b64=signature_b64,
    )


# ---------------------------------------------------------------------------
# Security Checks
# ---------------------------------------------------------------------------

def check_alg_none(header: Dict[str, Any], findings: List[Finding]) -> None:
    """Check for alg=none and missing alg field."""
    alg = header.get("alg", "")
    
    if not isinstance(alg, str):
        findings.append(Finding(
            "INFO",
            "Invalid 'alg' header (not a string)",
            f"alg value: {repr(alg)}. Expected a string like 'HS256'.",
            "Server is violating JWT spec. Manual testing required."
        ))
        return
    
    if alg.lower() == "none":
        findings.append(Finding(
            "CRITICAL",
            "Algorithm set to 'none'",
            "The header declares alg=none, meaning the token claims to require "
            "no signature verification at all.",
            "Confirm whether the server actually accepts this token as-is "
            "(strip the signature and resend). If accepted, this is a full "
            "authentication bypass — report as critical."
        ))
    elif alg == "":
        findings.append(Finding(
            "MEDIUM",
            "Missing 'alg' field",
            "The header does not declare an algorithm at all.",
            "Some libraries default to a permissive behavior when alg is "
            "absent. Worth testing how the server's verification code "
            "handles this."
        ))


def check_typ_header(header: Dict[str, Any], findings: List[Finding]) -> None:
    """Check the typ header per RFC 8725."""
    typ = header.get("typ")
    if typ is not None and not isinstance(typ, str):
        findings.append(Finding(
            "INFO",
            "Invalid 'typ' header (not a string)",
            f"typ value: {repr(typ)}.",
            "Server is violating JWT spec. Manual testing required."
        ))
        return
    
    if typ is not None and typ.upper() != "JWT":
        findings.append(Finding(
            "INFO",
            f"Non-standard 'typ' header ('{typ}')",
            "RFC 8725 recommends verifying typ is exactly 'JWT'. A "
            "non-standard value can indicate the token is meant for a "
            "different purpose (e.g. a different JOSE-based token type) "
            "and may cause parsing/validation quirks if the server doesn't "
            "check it either.",
            "Check whether the server enforces typ at all — if not, test "
            "whether tokens crafted for another purpose are accepted here."
        ))


def check_alg_confusion(header: Dict[str, Any], findings: List[Finding]) -> None:
    """Check for asymmetric algorithms that may be vulnerable to alg confusion."""
    alg = header.get("alg", "")
    if not isinstance(alg, str):
        return
    
    if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"):
        findings.append(Finding(
            "INFO",
            f"Asymmetric algorithm in use ({alg})",
            "This token is signed with an asymmetric algorithm. If the "
            "server's verification code does not strictly pin the expected "
            "algorithm, it may be possible to re-sign a forged token using "
            "HS256 with the server's public key treated as an HMAC secret "
            "(classic 'alg confusion' / CVE-2015-9235-style attack).",
            "Manual test required: obtain the public key (JWKS endpoint, "
            "cert, etc.), re-sign a modified payload as HS256 using that "
            "key as the HMAC secret, and see if the server accepts it."
        ))


def check_kid_header(header: Dict[str, Any], findings: List[Finding]) -> None:
    """Check for kid, jku, x5u, and jwk headers."""
    if "kid" in header:
        kid = header["kid"]
        findings.append(Finding(
            "INFO",
            "'kid' header present",
            f"kid value: {repr(kid)}. The 'kid' (Key ID) header is "
            "frequently used by servers to look up the verification key "
            "from a file path, database query, or command — making it a "
            "known injection point (path traversal, SQLi, command injection).",
            "Manually test kid with path traversal payloads, SQL metacharacters, "
            "and 'point it at a key you control' tricks (e.g. kid pointing at "
            "/dev/null combined with alg=HS256 and empty secret)."
        ))
    
    if "jku" in header or "x5u" in header:
        findings.append(Finding(
            "MEDIUM",
            "External key reference in header (jku/x5u)",
            "The header references an external URL for key material. If the "
            "server fetches this URL without validating it against an "
            "allowlist, an attacker can host their own key and self-sign "
            "tokens.",
            "Test whether jku/x5u can be pointed at an attacker-controlled URL."
        ))
    
    if "jwk" in header:
        findings.append(Finding(
            "MEDIUM",
            "Embedded JWK header present",
            "Header contains an embedded public key. If the server trusts this "
            "blindly, tokens can be forged.",
            "Test if the server uses this key for verification without validation."
        ))
    
    if "crit" in header:
        crit = header["crit"]
        findings.append(Finding(
            "HIGH",
            "'crit' header present (critical extensions)",
            f"crit value: {repr(crit)}. This header lists extensions that MUST "
            "be understood by the verifier.",
            "If the server doesn't validate crit, it may ignore critical "
            "security features. Check for CVE-2018-0114-like vulnerabilities."
        ))
    
    if "cty" in header:
        cty = header["cty"]
        findings.append(Finding(
            "INFO",
            "'cty' (Content Type) header present",
            f"cty value: {repr(cty)}. Indicates this is a nested JWT.",
            "If cty is set to 'JWT', the payload contains another JWT. "
            "Test for parsing confusion in nested JWTs."
        ))


def safe_timestamp(timestamp: Any, claim_name: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Safely convert a timestamp claim to an integer.
    Returns (timestamp_value, error_message).
    """
    if timestamp is None:
        return None, None
    
    if not isinstance(timestamp, (int, float)):
        try:
            timestamp = int(timestamp)
        except (TypeError, ValueError):
            return None, f"{claim_name} is not a number: {repr(timestamp)}"
    
    # Check for overflow
    try:
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None, f"{claim_name} value is out of range: {timestamp}"
    
    return int(timestamp), None


def check_claims(payload: Dict[str, Any], findings: List[Finding]) -> None:
    """Check JWT claims: exp, iat, nbf, iss, aud, sub, jti."""
    now = int(time.time())
    
    # --- exp (Expiration) ---
    if "exp" in payload:
        exp, err = safe_timestamp(payload["exp"], "exp")
        if err:
            findings.append(Finding(
                "INFO",
                "Invalid 'exp' claim",
                err,
                "Server is violating JWT spec. Manual testing required."
            ))
            return
        elif exp is not None:
            exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
            if exp < now:
                findings.append(Finding(
                    "LOW",
                    "Token is expired",
                    f"exp claim ({exp_dt.isoformat()}) is in the past.",
                    "Expired at time of analysis — not directly exploitable, but "
                    "confirm the server actually rejects expired tokens (some "
                    "custom implementations forget to check exp)."
                ))
            elif "iat" in payload:
                iat, _ = safe_timestamp(payload["iat"], "iat")
                if iat is not None:
                    total_lifetime_days = (exp - iat) / 86400
                    if total_lifetime_days > 1:
                        findings.append(Finding(
                            "LOW",
                            "Long token lifetime",
                            f"Token was issued with a total lifetime of approximately "
                            f"{total_lifetime_days:.1f} days (exp - iat).",
                            "Long-lived access tokens increase the impact window if "
                            "a token is leaked. Compare against the program's "
                            "expected session duration."
                        ))
            else:
                remaining_days = (exp - now) / 86400
                if remaining_days > 1:
                    findings.append(Finding(
                        "LOW",
                        "Cannot compute total token lifetime (no 'iat')",
                        f"No iat claim, so total issued lifetime is unknown. "
                        f"Remaining validity from now is approximately "
                        f"{remaining_days:.1f} days.",
                        "If you need total lifetime for a report, request the "
                        "server's token-issuance logs/docs, or issue a fresh token "
                        "and record the timestamp yourself."
                    ))
    else:
        findings.append(Finding(
            "MEDIUM",
            "No 'exp' (expiration) claim",
            "This token has no expiration, meaning it may be valid forever "
            "once issued.",
            "Confirm the server actually enforces its own session expiry "
            "elsewhere. If not, a leaked/stolen token never becomes invalid."
        ))
    
    # --- iat (Issued At) ---
    if "iat" not in payload:
        findings.append(Finding(
            "LOW",
            "No 'iat' (issued-at) claim",
            "Missing iat makes it harder to reason about token age or "
            "detect replay of very old tokens.",
            "Informational — note in write-up if relevant to a broader "
            "authentication weakness."
        ))
    else:
        iat, err = safe_timestamp(payload["iat"], "iat")
        if err:
            findings.append(Finding(
                "INFO",
                "Invalid 'iat' claim",
                err,
                "Server is violating JWT spec. Manual testing required."
            ))
    
    # --- nbf (Not Before) ---
    if "nbf" in payload:
        nbf, err = safe_timestamp(payload["nbf"], "nbf")
        if err:
            findings.append(Finding(
                "INFO",
                "Invalid 'nbf' claim",
                err,
                "Server is violating JWT spec. Manual testing required."
            ))
        elif nbf is not None and nbf > now:
            findings.append(Finding(
                "INFO",
                "Token not yet valid (nbf in future)",
                f"nbf claim is set to {datetime.fromtimestamp(nbf, tz=timezone.utc).isoformat()}.",
                "Informational only."
            ))
    
    # --- iss (Issuer) ---
    if "iss" not in payload:
        findings.append(Finding(
            "LOW",
            "No 'iss' (issuer) claim",
            "Missing issuer makes it harder to validate token origin.",
            "If the server enforces iss, test for misconfigurations."
        ))
    elif not isinstance(payload["iss"], str):
        findings.append(Finding(
            "INFO",
            "Invalid 'iss' claim (not a string)",
            f"iss value: {repr(payload['iss'])}",
            "Server is violating JWT spec. Manual testing required."
        ))
    
    # --- aud (Audience) ---
    if "aud" not in payload:
        findings.append(Finding(
            "LOW",
            "No 'aud' (audience) claim",
            "Missing audience claim means token might be valid across multiple services.",
            "Test for cross-service token reuse."
        ))
    elif not isinstance(payload["aud"], (str, list)):
        findings.append(Finding(
            "INFO",
            "Invalid 'aud' claim (not a string or list)",
            f"aud value: {repr(payload['aud'])}",
            "Server is violating JWT spec. Manual testing required."
        ))
    
    # --- sub (Subject) ---
    if "sub" not in payload:
        findings.append(Finding(
            "INFO",
            "No 'sub' (subject) claim",
            "Missing subject identifier.",
            "Informational — note in write-up if relevant."
        ))
    elif not isinstance(payload["sub"], str):
        findings.append(Finding(
            "INFO",
            "Invalid 'sub' claim (not a string)",
            f"sub value: {repr(payload['sub'])}",
            "Server is violating JWT spec. Manual testing required."
        ))
    
    # --- jti (JWT ID) ---
    if "jti" not in payload:
        findings.append(Finding(
            "INFO",
            "No 'jti' (JWT ID) claim",
            "Missing unique identifier makes replay detection harder.",
            "If the server doesn't check jti, tokens may be replayable."
        ))
    elif not isinstance(payload["jti"], str):
        findings.append(Finding(
            "INFO",
            "Invalid 'jti' claim (not a string)",
            f"jti value: {repr(payload['jti'])}",
            "Server is violating JWT spec. Manual testing required."
        ))


# ---------------------------------------------------------------------------
# HMAC Secret Cracking
# ---------------------------------------------------------------------------

def attempt_hmac_crack(
    decoded: DecodedJWT,
    candidates: Generator[str, None, None],
    findings: List[Finding],
    use_color: bool = True,
    timeout: int = DEFAULT_CRACK_TIMEOUT,
) -> Tuple[Optional[str], int]:
    """
    Attempt to crack HMAC secret by brute force.
    Returns (cracked_secret, number_of_candidates_tried).
    """
    alg = decoded.header.get("alg", "")
    hash_fn = HMAC_ALGS.get(alg)
    if not hash_fn:
        return None, 0  # not an HMAC-signed token
    
    signing_input = f"{decoded.header_b64}.{decoded.payload_b64}".encode()
    signature = decoded.signature
    
    # Validate signature length
    digest_size = hash_fn().digest_size
    if len(signature) != digest_size:
        findings.append(Finding(
            "INFO",
            "Invalid signature length",
            f"Expected {digest_size} bytes, got {len(signature)} bytes.",
            "This may indicate a malformed token or a different signing algorithm."
        ))
        return None, 0
    
    tried = 0
    spinner = Spinner(use_color)
    start_time = time.time()
    
    for candidate in candidates:
        # Check timeout
        if time.time() - start_time > timeout:
            findings.append(Finding(
                "INFO",
                f"Secret cracking timed out after {timeout} seconds",
                f"Tried {tried} candidates. The secret may be strong or the wordlist too large.",
                "Try a smaller wordlist or increase timeout."
            ))
            spinner.clear()
            return None, tried
        
        spinner.update(tried, alg)
        
        if not candidate:
            # Empty secret check
            computed = hmac.new(b"", signing_input, hash_fn).digest()
            if hmac.compare_digest(computed, signature):
                findings.append(Finding(
                    "CRITICAL",
                    "Empty HMAC secret accepted",
                    "The token verifies successfully with an EMPTY signing "
                    "secret. This is equivalent to no signature protection "
                    "at all.",
                    "Report immediately — this is as severe as alg=none. "
                    "Recommend the server reject empty/blank secrets and "
                    "rotate to a proper high-entropy key."
                ))
                spinner.clear()
                return "(empty string)", tried + 1
            tried += 1
            continue
        
        tried += 1
        computed = hmac.new(candidate.encode("utf-8"), signing_input, hash_fn).digest()
        if hmac.compare_digest(computed, signature):
            findings.append(Finding(
                "CRITICAL",
                "Weak HMAC secret cracked",
                f"The signing secret was recovered: '{candidate}'. This "
                "means anyone can forge arbitrary valid tokens (privilege "
                "escalation, account takeover, full auth bypass).",
                "Report immediately with high severity. Include the forging "
                "PoC and recommend rotating to a long, random, high-entropy "
                "secret plus rate-limiting/monitoring for auth anomalies."
            ))
            spinner.clear()
            return candidate, tried
    
    spinner.clear()
    return None, tried


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_findings(decoded: DecodedJWT) -> List[Finding]:
    """Run all checks and return a list of findings."""
    findings: List[Finding] = []
    
    check_alg_none(decoded.header, findings)
    check_typ_header(decoded.header, findings)
    check_alg_confusion(decoded.header, findings)
    check_kid_header(decoded.header, findings)
    check_claims(decoded.payload, findings)
    
    return findings


def print_report(
    decoded: DecodedJWT,
    findings: List[Finding],
    cracked_secret: Optional[str] = None,
    wordlist_size: int = 0,
    tried_crack: bool = False,
    use_color: bool = True,
) -> None:
    """Print the analysis report."""
    print_banner(use_color)
    
    section_header("DECODED TOKEN", use_color)
    print(colorize("\n  Header:", COLOR_BOLD, use_color))
    for line in json.dumps(decoded.header, indent=2).splitlines():
        print("   " + line)
    print(colorize("\n  Payload:", COLOR_BOLD, use_color))
    for line in json.dumps(decoded.payload, indent=2).splitlines():
        print("   " + line)
    
    if tried_crack:
        print()
        section_header("SECRET CRACKING", use_color)
        print(f"\n  Candidates tried: {wordlist_size}")
        if cracked_secret is not None:
            print(colorize(f"  ✗ SECRET RECOVERED: '{cracked_secret}'", 
                          SEVERITY_COLOR["CRITICAL"], use_color))
        else:
            print(colorize("  ✓ No match in wordlist", 
                          SEVERITY_COLOR["LOW"], use_color) +
                  colorize(" (doesn't prove it's strong — try a bigger wordlist)", 
                          COLOR_DIM, use_color))
    
    print()
    section_header("FINDINGS", use_color)
    if not findings:
        print(colorize("\n  No issues flagged by automated checks.", COLOR_GREEN, use_color))
    else:
        findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        for i, f in enumerate(findings_sorted, 1):
            sev_color = SEVERITY_COLOR.get(f.severity, COLOR_DIM)
            print(f"\n  {i}. {colorize(f' {f.severity} ', sev_color, use_color)} "
                  f"{colorize(f.title, COLOR_BOLD, use_color)}")
            print(f"     {colorize('Detail:', COLOR_DIM, use_color)}         {f.detail}")
            print(f"     {colorize('Recommendation:', COLOR_DIM, use_color)} {f.recommendation}")
    
    print()
    print(colorize("═" * 70, COLOR_DIM, use_color))
    print(risk_verdict(findings, use_color))
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary_parts = [
        colorize(f"{sev}: {counts[sev]}", SEVERITY_COLOR.get(sev, COLOR_DIM), use_color)
        for sev in SEVERITY_ORDER if sev in counts
    ]
    print(" " + "   ".join(summary_parts) if summary_parts else " no findings")
    print(colorize("═" * 70, COLOR_DIM, use_color))


# ---------------------------------------------------------------------------
# Wordlist Streaming
# ---------------------------------------------------------------------------

def stream_wordlist(path: str) -> Generator[str, None, None]:
    """Stream a wordlist file line by line."""
    if os.path.getsize(path) > MAX_WORDLIST_SIZE:
        raise ValueError(f"Wordlist file exceeds maximum size ({MAX_WORDLIST_SIZE} bytes)")
    
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            yield line.strip()


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="jaws.py",
        description="J.A.W.S. — JWT Analysis & Weakness Scanner. "
                    "A recon tool for bug bounty / API security testing."
    )
    parser.add_argument("token", nargs="?", help="The JWT string to analyze")
    parser.add_argument("--file", help="Path to a file containing the JWT (first line used)")
    parser.add_argument("--wordlist", help="Path to a wordlist file for HMAC secret cracking. "
                                           "If omitted, a small built-in list is used.")
    parser.add_argument("--no-crack", action="store_true",
                        help="Skip the secret-cracking step entirely.")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored/animated output (e.g. when piping to a file).")
    parser.add_argument("--timeout", type=int, default=DEFAULT_CRACK_TIMEOUT,
                        help=f"Timeout for secret cracking in seconds (default: {DEFAULT_CRACK_TIMEOUT})")
    args = parser.parse_args()
    
    # Auto-disable color if output isn't a real terminal
    use_color = sys.stdout.isatty() and not args.no_color
    
    # --- Read token ---
    token: Optional[str] = None
    
    if args.file:
        try:
            if os.path.getsize(args.file) > MAX_JWT_FILE_SIZE:
                print(f"[!] Token file exceeds maximum size ({MAX_JWT_FILE_SIZE} bytes)", file=sys.stderr)
                sys.exit(1)
            with open(args.file, encoding="utf-8", errors="ignore") as fh:
                token = fh.readline().strip()
        except OSError as e:
            print(f"[!] Cannot read file: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.token:
        token = args.token
    
    if not token:
        parser.error("Provide a token as an argument or via --file")
    
    # --- Parse JWT ---
    try:
        decoded = parse_jwt(token)
    except ValueError as e:
        print(f"[!] Failed to parse token: {e}", file=sys.stderr)
        sys.exit(1)
    
    # --- Analyze ---
    findings = generate_findings(decoded)
    
    # --- Crack (optional) ---
    cracked_secret = None
    wordlist_size = 0
    tried_crack = False
    
    if not args.no_crack and decoded.header.get("alg", "") in HMAC_ALGS:
        tried_crack = True
        try:
            if args.wordlist:
                candidates = stream_wordlist(args.wordlist)
            else:
                candidates = (s for s in DEFAULT_WEAK_SECRETS)
            
            cracked_secret, wordlist_size = attempt_hmac_crack(
                decoded, candidates, findings, use_color, args.timeout
            )
        except (OSError, ValueError) as e:
            print(f"[!] Error during cracking: {e}", file=sys.stderr)
            sys.exit(1)
    
    # --- Report ---
    print_report(
        decoded=decoded,
        findings=findings,
        cracked_secret=cracked_secret,
        wordlist_size=wordlist_size,
        tried_crack=tried_crack,
        use_color=use_color,
    )


if __name__ == "__main__":
    main()
