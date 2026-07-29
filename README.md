# J.A.W.S - JWT Analysis & Weakness Scanner

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![Tests](https://img.shields.io/badge/tests-pytest-blueviolet)
[![CI](https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner/actions/workflows/ci.yml)

**A zero-dependency Python CLI that decodes a JWT, audits it against a checklist of real-world weaknesses, and (optionally) attempts to recover weak HMAC signing secrets. Built for bug bounty and API pentesting workflows.**

I built J.A.W.S mid-engagement, during a live bug bounty test, after realizing I was manually decoding JWTs and re-running the same handful of checks (algorithm confusion, weak secrets, missing claims) on every target. I turned that repetitive checklist into a tool that runs in seconds. It's written entirely against Python's standard library, so there's nothing to install beyond Python itself.

## Example

```bash
$ python3 jaws.py <token>

DECODED TOKEN
Header: { "alg": "HS256", "typ": "JWT" }
Payload: { "username": "admin", "role": "user", "exp": 1893456000 }

FINDINGS

CRITICAL: Weak HMAC secret cracked
Detail: The signing secret was recovered.
Recommendation: Rotate the signing secret immediately.

CRITICAL: 1
```

## Why this exists

Most JWT tooling either lives inside a Burp extension or wraps a full exploitation framework. J.A.W.S is intentionally narrow: it's a fast, scriptable **recon and triage** layer you point at a token before you decide where to spend your manual testing time. It tells you where the weaknesses likely are, you still verify and exploit them yourself.

## Features

- **Structural decoding**: instantly readable header/payload breakdown, no external decoder needed
- **JOSE header audit**: flags risky configurations across 8 header fields (`alg`, `kid`, `jku`, `x5u`, `jwk`, `crit`, `cty`, `typ`)
- **Claim hygiene checks**: catches missing/weak `exp`, `aud`, `iss`, `iat`
- **HMAC secret cracking**: tests HS256/384/512 tokens against a built-in wordlist or your own, with streaming I/O (no loading huge wordlists into memory), timeout protection, and constant-time comparison
- **Zero dependencies**: runs anywhere Python 3.10+ runs, no `pip install` required
- **Scriptable output**: `--no-color` for clean piping into logs, files, or CI

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

## Design decisions & trade-offs

A few choices in here were deliberate, so I'm writing down the reasoning instead of leaving it implicit.

### Why zero dependencies?

I stuck to Python's standard library only. A few reasons:

- It just works. No `pip install` step, no waiting on a CI runner, no dependency conflicts
- No supply chain risk from pulling in random third-party packages
- Behaves the same no matter what system you drop it on

The cost is I had to handle base64 padding manually and roll my own JWT decoding instead of importing something like PyJWT. Worth it, though, since this tool is meant to run in places like CI runners, throwaway containers, and bug bounty VMs, where `pip install` is sometimes blocked, slow, or just not worth the hassle for a quick check.

### Why stream the wordlist instead of loading it all at once?

The wordlist loader yields lines one at a time instead of reading the whole file into memory. That matters once you point it at something like `rockyou.txt`, which has 10M+ lines, on a low-memory box; loading it all up front would just crash. The built-in list stays intentionally small; if you want real firepower, pass in your own with `--wordlist`.

### Constant-time comparison for the signature check

I used `hmac.compare_digest()` instead of a plain `==`. A regular string comparison bails out at the first mismatched byte, which in theory leaks timing information an attacker could use to guess the secret one character at a time. Doesn't really matter for my own offline cracking loop, but it's the correct pattern, and I wanted the code to model it properly since this is exactly the mistake to watch for if you ever see it in a server's actual auth check.

### Why no RS256 cracking?

HS256/384/512 use a shared secret, so brute-forcing it is at least theoretically possible. RS256/ES256 use a private key instead, and brute-forcing that is computationally out of reach with current hardware, so there's no point pretending to support it. J.A.W.S. just checks the `alg` field and skips the cracking step automatically for anything starting with `RS` or `ES`.

### What I'd change if I rebuilt this

- A plugin system for custom checks, since JWT claims are pretty app-specific and a one-size-fits-all check list only gets you so far
- JWK and JWE support
- Parallelized wordlist cracking, since right now it's single-threaded and slower than it needs to be

## Project structure

```text
JWT-Analysis-Weakness-Scanner/
├── jaws.py                 # Scanner: decoding, header/claim checks, HMAC cracking, CLI
├── tests/
│   └── test_jaws.py        # pytest suite covering parsing and finding detection
├── requirements.txt        # No runtime deps; documents dev/test deps
├── LICENSE                 # MIT
└── README.md
```

The core logic and test suite are unit-tested with `pytest` (see `tests/test_jaws.py`). Token parsing, `alg=none` detection, missing/expired `exp` handling, and finding generation are all covered.

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
