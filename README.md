# J.A.W.S - JWT Analysis & Weakness Scanner

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![Tests](https://img.shields.io/badge/tests-pytest-blueviolet)

**A zero-dependency Python CLI that decodes a JWT, audits it against a checklist of real-world weaknesses, and (optionally) attempts to recover weak HMAC signing secrets  built for bug bounty and API pentesting workflows.**

I built J.A.W.S mid-engagement, during a live bug bounty test, after realizing I was manually decoding JWTs and re-running the same handful of checks (algorithm confusion, weak secrets, missing claims) on every target. I turned that repetitive checklist into a tool that runs in seconds. It's written entirely against Python's standard library, so there's nothing to install beyond Python itself.

```
$ python3 jaws.py <token>

DECODED TOKEN
Header:  { "alg": "HS256", "typ": "JWT" }
Payload: { "username": "admin", "role": "user", "exp": 1893456000 }

FINDINGS
1. CRITICAL — Weak HMAC secret cracked
   Detail: The signing secret was recovered.
   Recommendation: Rotate the signing secret immediately.

CRITICAL: 1
```

## Why this exists

Most JWT tooling either lives inside a Burp extension or wraps a full exploitation framework. J.A.W.S is intentionally narrow: it's a fast, scriptable **recon and triage** layer you point at a token before you decide where to spend your manual testing time. It tells you where the weaknesses likely are, you still verify and exploit them yourself.

## Features

- **Structural decoding** — instantly readable header/payload breakdown, no external decoder needed
- **JOSE header audit** — flags risky configurations across 8 header fields (`alg`, `kid`, `jku`, `x5u`, `jwk`, `crit`, `cty`, `typ`)
- **Claim hygiene checks** — catches missing/weak `exp`, `aud`, `iss`, `iat`
- **HMAC secret cracking** — tests HS256/384/512 tokens against a built-in wordlist or your own, with streaming I/O (no loading huge wordlists into memory), timeout protection, and constant-time comparison
- **Zero dependencies** — runs anywhere Python 3.10+ runs, no `pip install` required
- **Scriptable output** — `--no-color` for clean piping into logs, files, or CI

## Install & run

```bash
git clone https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner.git
cd JWT-Analysis-Weakness-Scanner
python3 jaws.py <YOUR_JWT_TOKEN>
```

No virtual environment or dependency install needed for normal use.

## Usage

```bash
# Analyze a token directly
python3 jaws.py <JWT_TOKEN>

# Analyze a token stored in a file (first line used)
python3 jaws.py --file token.txt

# Crack against a custom wordlist
python3 jaws.py <JWT_TOKEN> --wordlist secrets.txt

# Skip secret cracking, structural analysis only
python3 jaws.py <JWT_TOKEN> --no-crack

# Disable colored/animated output (for CI or log files)
python3 jaws.py <JWT_TOKEN> --no-color

# Adjust the cracking timeout (default 60s)
python3 jaws.py <JWT_TOKEN> --timeout 120
```

## What it checks

| Header / Claim | Risk it's checking for |
|---|---|
| `alg` | `alg=none` and other insecure algorithm configurations |
| `kid` | Key-lookup injection attack surface |
| `jku` / `x5u` | Untrusted external key/certificate references |
| `jwk` | Embedded public keys accepted at face value |
| `crit` | Unrecognized critical extension usage |
| `typ` / `cty` | Type inconsistency, nested-JWT indicators |
| `exp` | Tokens that never expire |
| `aud` / `iss` | Missing audience or issuer validation |
| `iat` | No way to track token age |
| HMAC secret | Weak/guessable HS256/384/512 signing keys |

## How it works

1. Decode the token's structure (header, payload, signature)
2. Run the JOSE header audit
3. Run the security-relevant claim checks
4. Aggregate everything into severity-ranked findings
5. Optionally attempt HMAC secret recovery
6. Print a readable findings report (or pipe it elsewhere with `--no-color`)

## Project structure

```
JWT-Analysis-Weakness-Scanner/
├── jaws.py              # Scanner: decoding, header/claim checks, HMAC cracking, CLI
├── tests/
│   └── test_jaws.py     # pytest suite covering parsing and finding detection
├── requirements.txt     # No runtime deps; documents dev/test deps
├── LICENSE              # MIT
└── README.md
```

The core logic and test suite are unit-tested with `pytest` (see `tests/test_jaws.py`)  token parsing, `alg=none` detection, missing/expired `exp` handling, and finding generation are all covered.

## Limitations by design

This is a recon and analysis tool, not an exploitation framework. It intentionally does **not**:

- Automatically exploit anything it finds
- Attack remote systems
- Bypass authentication on its own
- Replace a thorough manual pentest

Treat its output as a starting point for investigation, always verify findings manually against the actual target.

## Legal

Intended for authorized penetration testing, bug bounty programs, security research, and learning. Only run it against systems you own or have explicit permission to test.


---

If this is useful to you, a star on the repo is appreciated.
