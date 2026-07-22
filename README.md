# J.A.W.S — JWT Analysis & Weakness Scanner

A lightweight, dependency-free command-line tool for analyzing JSON Web Tokens and surfacing common security weaknesses. Built for API security testing, bug bounty recon, and JWT assessments.

I built J.A.W.S because I kept manually decoding JWTs and checking the same handful of things during pentests and bug bounty work, algorithm misconfigurations, weak signing secrets, missing claims, so I turned that repetitive checklist into a tool. It's written entirely in Python's standard library, so there's nothing to install beyond Python itself.

## What it does

Point J.A.W.S at a JWT and it will:

- Decode the header and payload for quick inspection
- Flag algorithm-related issues, including `alg=none` and algorithm confusion risks
- Check the JOSE header for suspicious or risky fields
- Flag missing or weak security claims (expiration, audience, issuer, etc.)
- Optionally attempt to crack HMAC-signed tokens against a wordlist

It's a recon and analysis tool, not an exploitation framework, it tells you where the weaknesses likely are so you can verify and act on them manually.

## JOSE header checks

| Header | What it's checking for |
|--------|------------------------|
| `alg`  | Insecure algorithm configurations |
| `typ`  | JWT type consistency |
| `kid`  | Key lookup attack surface |
| `jku`  | External key references |
| `x5u`  | Certificate URL references |
| `jwk`  | Embedded public keys |
| `crit` | Critical extension usage |
| `cty`  | Nested JWT indicators |

## HMAC secret testing

For HS256, HS384, and HS512 tokens, J.A.W.S can attempt to recover the signing secret using either a built-in list of common weak secrets or a custom wordlist. It streams the wordlist rather than loading it all into memory, has timeout protection, and uses constant-time comparison when checking signatures.

## Installation

```bash
git clone https://github.com/MuizRecon/jaws-jwt-scanner.git
cd jaws-jwt-scanner
```

No dependencies, no virtual environment required — just Python 3.10 or newer.

## Usage

**Analyze a token directly:**

```bash
python3 jaws.py <JWT_TOKEN>
```

**Analyze a token stored in a file:**

```bash
python3 jaws.py --file token.txt
```

**Test against a custom wordlist:**

```bash
python3 jaws.py <JWT_TOKEN> --wordlist secrets.txt
```

**Skip secret cracking entirely** (useful if you just want the structural analysis):

```bash
python3 jaws.py <JWT_TOKEN> --no-crack
```

**Disable colored output** (handy for piping into logs or CI):

```bash
python3 jaws.py <JWT_TOKEN> --no-color
```

## Example output

```
============================================================

DECODED TOKEN

Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "username": "admin",
  "role": "user",
  "exp": 1893456000
}


FINDINGS

1. CRITICAL — Weak HMAC secret cracked

Detail:
The signing secret was recovered.

Recommendation:
Rotate the signing secret immediately.

============================================================

CRITICAL: 1
```

## Vulnerabilities it looks for

| Issue | Description |
|-------|-------------|
| `alg=none` | Unsigned JWT accepted as valid |
| Weak HMAC secret | Easily guessable signing key |
| Algorithm confusion | Risky asymmetric/symmetric mixing |
| Missing `exp` | Token never expires |
| Missing `aud` | No audience validation |
| Missing `iss` | No issuer validation |
| Missing `iat` | No way to track token age |
| `kid` header risks | Potential key lookup injection |
| `jku` / `x5u` risks | Untrusted external key references |

## Project structure

```
jaws-jwt-scanner/
├── jaws.py              # Main scanner
├── README.md            # Documentation
├── LICENSE              # MIT License
└── requirements.txt     # Dependencies (none, but listed for clarity)
```

## How it works

J.A.W.S follows a fairly standard JWT assessment workflow:

1. Decode the token's structure
2. Analyze the JOSE header
3. Inspect the security-relevant claims
4. Flag likely weaknesses
5. Attempt HMAC secret cracking (optional)
6. Generate a readable findings report

## Limitations

This is a recon and analysis tool. It intentionally does **not**:

- Automatically exploit anything it finds
- Attack remote systems
- Bypass authentication on its own
- Replace a thorough manual pentest

Treat its output as a starting point for investigation, not a final verdict — always verify findings manually against the actual target.

## Legal

J.A.W.S is intended for authorized penetration testing, bug bounty programs, security research, and learning. Only run it against systems you own or have explicit permission to test. Unauthorized use against systems you don't have permission for may be illegal.

## About

I'm MuizRecon, a cybersecurity researcher focused on API security, JWT security, and bug bounty hunting. This tool grew out of my own workflow doing web application security assessments.

- GitHub: [github.com/MuizRecon](https://github.com/MuizRecon)

## Roadmap

Things I'd like to add:

- JSON report export
- A JWT verification mode
- Public key analysis
- More claim checks
- CI/CD integration
- Automated security scoring

---

If you find this useful, a star on the repo is always appreciated.
