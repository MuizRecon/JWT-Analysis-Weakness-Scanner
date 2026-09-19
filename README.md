# J.A.W.S. | JWT Analysis & Weakness Scanner

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Dependencies](https://img.shields.io/badge/runtime%20dependencies-zero-brightgreen)](#why-zero-dependencies)
[![Tests](https://img.shields.io/badge/tests-pytest-blueviolet)](tests/)
[![CI](https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner/actions/workflows/ci.yml)

**A zero-dependency Python CLI that decodes a JWT, audits it against a checklist of real-world weaknesses, and (optionally) attempts to recover weak HMAC signing secrets. Built for bug bounty and API pentesting workflows.**

I built J.A.W.S. mid-engagement, during a live bug bounty test, after realizing I was manually decoding JWTs and re-running the same handful of checks (weak secrets, `alg=none`, missing claims) on every target. I turned that repetitive checklist into a tool that runs in seconds. It's written entirely against Python's standard library, so there are no third-party packages to install.

## Quick start

```
git clone https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner.git
cd JWT-Analysis-Weakness-Scanner
pip install .
jaws <YOUR_JWT_TOKEN>
```

`pip install .` only installs J.A.W.S. itself and adds the `jaws` command. It downloads nothing else. If you'd rather not install anything, run it straight from the clone:

```
PYTHONPATH=src python3 -m jaws.cli <YOUR_JWT_TOKEN>
```

Requires Python 3.10 or newer.

## Example

This token is a demo I created for this README. It is signed with a deliberately weak secret and is not a real credential, so you can paste it in and get the same result:

```
jaws eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6InVzZXIiLCJleHAiOjE4OTM0NTYwMDB9.OSgmBhK3UWp9lP4EsFJntNuU16anUD_0-DrirUVLVKM
```

Output:

```
=== DECODED TOKEN ===
Header: {'alg': 'HS256', 'typ': 'JWT'}
Payload: {'username': 'admin', 'role': 'user', 'exp': 1893456000}
Signature: OSgmBhK3UWp9lP4EsFJn...

=== HMAC CRACKING ===
✓ Secret recovered: secret (in 0.00s)

=== FINDINGS ===
[CRITICAL] Weak HMAC secret cracked
  Detail: The signing secret was recovered: "secret".
  Recommendation: Rotate the signing secret immediately.
  Field: signature

[MEDIUM] Symmetric algorithm in use
  Detail: Using HS256 means the same secret signs and verifies.
  Recommendation: Consider RS256 or ES256 for production systems.
  Field: alg

[MEDIUM] Missing audience (aud) claim
  Detail: No audience restriction, token may be used across services.
  Recommendation: Define aud to restrict token usage.
  Field: aud

[LOW] Missing issuer (iss) claim
  Detail: No issuer specified, origin cannot be verified.
  Recommendation: Include iss to establish trust.
  Field: iss

[LOW] Missing issued-at (iat) claim
  Detail: Token age cannot be tracked.
  Recommendation: Include iat to support token age policies.
  Field: iat


Summary: {'CRITICAL': 1, 'HIGH': 0, 'MEDIUM': 2, 'LOW': 2, 'INFO': 0}

=== RECOMMENDATIONS ===
CRITICAL: Rotate the signing secret immediately.
```

## Why this exists

Most JWT tooling either lives inside a Burp extension or wraps a full exploitation framework. Toolkits like jwt_tool and jwt-hack cover more attacks than J.A.W.S. does, and that's fine, because J.A.W.S. is intentionally narrow. It's a fast, scriptable **recon and triage** layer you point at a token before you decide where to spend your manual testing time. It tells you where the weaknesses likely are. You still verify and exploit them yourself.

## Usage

```
# Analyze a token directly
jaws <JWT_TOKEN>

# Analyze a token stored in a file (first line is used)
jaws --file token.txt

# Crack against a custom wordlist
jaws <JWT_TOKEN> --wordlist secrets.txt

# Skip secret cracking, structural analysis only
jaws <JWT_TOKEN> --no-crack

# Disable colored output (for CI or log files)
jaws <JWT_TOKEN> --no-color

# Adjust the cracking timeout (default 60s)
jaws <JWT_TOKEN> --timeout 120

# Show the version and all options
jaws --version
jaws --help
```

Short flags: `-f` for `--file`, `-w` for `--wordlist`, `-t` for `--timeout`.

## What it checks

| Where | What it flags | Severity |
| ----- | ------------- | -------- |
| `alg` | `alg=none`, which allows forged tokens | Critical |
| `alg` | Symmetric algorithms (HS256, HS384, HS512) | Medium |
| `kid` | Key ID present, a possible path traversal or SQL injection surface | Medium |
| `jku` | External JWK Set URL referenced | High |
| `x5u` | External certificate URL referenced | High |
| `jwk` | Embedded public key that a server might accept at face value | High |
| `crit` | Critical extensions the server must understand | Medium |
| `cty` | `cty=JWT`, which suggests a nested token | Low |
| `exp` | Missing, so the token never expires | High |
| `exp` | Already expired | Info |
| `exp` | Expires in less than 5 minutes | Low |
| `aud` | Missing audience restriction | Medium |
| `iss` | Missing issuer | Low |
| `iat` | Missing issued-at time | Low |
| Signature | HMAC secret recovered from a wordlist | Critical |

For headers like `kid`, `jku`, `x5u`, `jwk` and `crit`, J.A.W.S. flags that they're present. Whether a given server actually handles them unsafely is something you have to test.

## How it works

1. Decode the token's structure (header, payload, signature)
2. Run the JOSE header audit
3. Run the claim checks
4. Optionally try to recover the HMAC secret (only for HS256, HS384 and HS512 tokens)
5. Print findings ranked by severity, then a short recommendation

## Design decisions & trade-offs

A few choices in here were deliberate, so I'm writing down the reasoning instead of leaving it implicit.

### Why zero dependencies?

I stuck to Python's standard library only. A few reasons:

- It just works. There's no dependency step, no version conflicts, and you can even run it straight from a clone.
- No supply chain risk from pulling in random third-party packages.
- It behaves the same no matter what system you drop it on.

The cost is that I had to handle base64 padding manually and write my own JWT decoding instead of importing something like PyJWT. It's worth it, since this tool is meant to run in places like CI runners, throwaway containers and bug bounty VMs, where installing packages is sometimes blocked, slow, or not worth the hassle for a quick check.

### Why stream the wordlist instead of loading it all at once?

The wordlist loader yields lines one at a time instead of reading the whole file into memory. That matters once you point it at something like `rockyou.txt`, which has 10M+ lines, on a low-memory box, because loading it all up front would crash. The built-in list is deliberately small (25 common secrets). If you want real firepower, pass in your own with `--wordlist`.

### Constant-time comparison for the signature check

I used `hmac.compare_digest()` instead of a plain `==`. A regular string comparison stops at the first mismatched byte, which in theory leaks timing information an attacker could use to guess the secret one character at a time. It doesn't really matter for my own offline cracking loop, but it's the correct pattern, and I wanted the code to model it properly, since it's exactly the mistake to watch for if you ever see it in a server's actual auth check.

### Why no RS256 cracking?

HS256, HS384 and HS512 use a shared secret, so brute-forcing it is at least theoretically possible. RS256 and ES256 use a private key instead, and brute-forcing that is computationally out of reach with current hardware, so there's no point pretending to support it. J.A.W.S. only attempts cracking on tokens whose `alg` starts with `HS` and skips the step for everything else.

### What I'd change if I rebuilt this

- A plugin system for custom checks, since JWT claims are pretty app-specific and a one-size-fits-all checklist only gets you so far
- JWK and JWE support
- Parallelized wordlist cracking, since right now it's single-threaded and slower than it needs to be

## Tests

The `pytest` suite covers token parsing, `alg=none` detection, missing `exp` handling, the symmetric algorithm finding, HMAC cracking (both a correct and a wrong wordlist), the cracked-secret finding, and malformed tokens. CI runs it on every push.

```
pip install pytest
pytest tests/ -v
```

## Project structure

```
JWT-Analysis-Weakness-Scanner/
├── src/jaws/
│   ├── cli.py              # Argument parsing and the main flow (entry point: jaws.cli:main)
│   ├── decoder.py          # Base64 handling and JWT decoding
│   ├── auditor.py          # Header and claim checks
│   ├── cracker.py          # HMAC secret cracking
│   ├── models.py           # Finding, DecodedToken, AnalysisResult
│   └── utils.py            # Output formatting, file and wordlist loading
├── tests/
│   └── test_jaws.py        # pytest suite
├── .github/workflows/
│   └── ci.yml              # Runs the tests on every push and pull request
├── pyproject.toml          # Packaging, installs the `jaws` command
├── requirements.txt        # Test dependencies only
├── LICENSE                 # MIT
└── README.md
```

## Limitations by design

This is a recon and analysis tool, not an exploitation framework. It intentionally does **not**:

- Automatically exploit anything it finds
- Attack remote systems or send any network requests
- Bypass authentication on its own
- Replace a thorough manual pentest

A few other things to know:

- It looks at the token only, so it can't tell you whether an API actually accepts a forged or modified token.
- It doesn't check for algorithm confusion (RS256 to HS256) or verify signatures against a real key.
- It exits with code 0 whenever the analysis completes, even when it finds something critical, so it won't fail a CI job on its own.

Treat its output as a starting point for investigation, and always verify findings manually against the actual target.

## Legal

Intended for authorized penetration testing, bug bounty programs, security research and learning. Only run it against systems you own or have explicit permission to test.

## Contributing

Bug reports and ideas are welcome. Open an issue, or send a pull request for anything on the "what I'd change" list above.

## License

MIT. See [LICENSE](LICENSE).

---

If this is useful to you, a star on the repo is appreciated.
