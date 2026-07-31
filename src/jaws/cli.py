import argparse
import sys
import time
from typing import Optional
from .models import AnalysisResult, DecodedToken, Severity
from .decoder import decode_token, is_token_valid_structure
from .auditor import JWTAuditor
from .cracker import HMACCracker
from .utils import print_finding, read_token_from_file, load_wordlist


BUILTIN_WORDLIST = [
    "secret", "password", "123456", "admin", "jwt", "key", "secretkey",
    "mysecret", "changeme", "letmein", "qwerty", "abc123", "monkey",
    "dragon", "master", "hello", "fuck", "love", "whatever", "test",
    "12345", "12345678", "123456789", "password123", "admin123",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='J.A.W.S. - JWT Analysis & Weakness Scanner',
        epilog='Zero-dependency JWT security analysis for bug bounty and API testing.'
    )
    parser.add_argument(
        'token',
        nargs='?',
        help='JWT token to analyze (or use --file)'
    )
    parser.add_argument(
        '--file', '-f',
        help='Read token from file (first line used)'
    )
    parser.add_argument(
        '--wordlist', '-w',
        help='Custom wordlist file for HMAC cracking'
    )
    parser.add_argument(
        '--no-crack',
        action='store_true',
        help='Skip HMAC secret cracking'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output (for CI/logs)'
    )
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=60,
        help='Timeout for HMAC cracking in seconds (default: 60)'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='J.A.W.S. 1.0.0'
    )
    return parser.parse_args()


def get_token(args: argparse.Namespace) -> Optional[str]:
    if args.token:
        return args.token.strip()
    if args.file:
        return read_token_from_file(args.file)
    return None


def get_wordlist(args: argparse.Namespace):
    if args.wordlist:
        return load_wordlist(args.wordlist)
    return BUILTIN_WORDLIST


def main() -> int:
    args = parse_args()

    token = get_token(args)
    if not token:
        print("Error: No token provided. Use --file or pass token directly.", file=sys.stderr)
        return 1

    if not is_token_valid_structure(token):
        print("Error: Invalid JWT format (expected 3 parts).", file=sys.stderr)
        return 1

    header, payload, signature = decode_token(token)
    if "error" in header or "error" in payload:
        print("Error: Failed to decode JWT – invalid header or payload format.", file=sys.stderr)
        return 1

    decoded = DecodedToken(
        raw=token,
        header=header,
        payload=payload,
        signature=signature
    )

    print("\n=== DECODED TOKEN ===")
    print(f"Header: {header}")
    print(f"Payload: {payload}")
    if signature:
        print(f"Signature: {signature[:20]}...")
    print()

    auditor = JWTAuditor()
    findings = auditor.audit(decoded)

    result = AnalysisResult(token=decoded, findings=findings)

    if not args.no_crack and header.get('alg', '').startswith('HS'):
        print("=== HMAC CRACKING ===")
        cracker = HMACCracker(decoded, timeout=args.timeout)
        wordlist = get_wordlist(args)
        start = time.time()
        recovered = cracker.crack(wordlist)
        elapsed = time.time() - start

        if recovered:
            result.secret_recovered = recovered
            result.cracking_time = elapsed
            print(f"✓ Secret recovered: {recovered} (in {elapsed:.2f}s)")
        else:
            print(f"✗ Secret not found (timeout: {args.timeout}s, elapsed: {elapsed:.2f}s)")
        print()

    print("=== FINDINGS ===")
    if not findings:
        print("No findings detected.")
    else:
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                         Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

        for finding in sorted_findings:
            print_finding(finding, use_color=not args.no_color)

        print(f"\nSummary: {result.summary}")

    print("\n=== RECOMMENDATIONS ===")
    if result.secret_recovered:
        print("CRITICAL: Rotate the signing secret immediately.")
    elif result.has_critical:
        print("Address critical findings before proceeding.")
    else:
        print("Review findings and prioritize based on severity.")

    return 0


if __name__ == '__main__':
    sys.exit(main())
