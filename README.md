# J.A.W.S. | JWT Analysis & Weakness Scanner

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Dependencies](https://img.shields.io/badge/runtime%20dependencies-zero-brightgreen)](#why-zero-dependencies)
[![Tests](https://img.shields.io/badge/tests-pytest-blueviolet)](tests/)
[![CI](https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner/actions/workflows/ci.yml)

A Python CLI with no runtime dependencies. It decodes a JWT, checks it against a list of common weaknesses, and can try to recover weak HMAC signing secrets. Built for bug bounty and API pentesting.

I wrote it during a live bug bounty test, after noticing I was decoding tokens by hand and running the same handful of checks on every target. I turned that routine into a tool that finishes in seconds. It only uses Python's standard library, so there is nothing to install beyond Python itself.

## Example

Command:

```
jaws <A_TEST_TOKEN_YOU_CREATED>
```

Output:

```
[PASTE THE REAL OUTPUT FROM A TEST TOKEN YOU CREATED.
 Include the recovered secret so people see what a hit looks like.]
```

## Why this exists

Most JWT tooling either lives inside a Burp extension or wraps a full exploitation framework. J.A.W.S. is deliberately narrow: it is a fast, scriptable recon and triage step you run on a token before deciding where to spend your manual testing time. It tells you where the weaknesses probably are. You still verify and exploit them yourself.


## What it does

It decodes the header, payload and signature into something readable, audits eight JOSE header fields (`alg`, `kid`, `jku`, `x5u`, `jwk`, `crit`, `cty`, `typ`), and checks the claims that matter for security (`exp`, `aud`, `iss`, `iat`). For HS256, HS384 and HS512 tokens it can also test the signing secret against a built-in wordlist or your own. Findings are ranked by severity. Use `--no-color` when piping output into logs or CI.

## Install & run

```
git clone https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner.git
cd JWT-Analysis-Weakness-Scanner
pip install .
jaws <YOUR_JWT_TOKEN>
```

Requires Python 3.10 or newer. There are no runtime dependencies, so `pip install .` only installs J.A.W.S. itself and adds the `jaws` command. `pytest` is only needed to run the tests.

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

# Disable colored/animated output (for CI or log files)
jaws <JWT_TOKEN> --no-color

# Adjust the cracking timeout (default 60s)
jaws <JWT_TOKEN> --timeout 120
```

## What it checks

| Header / Claim | Risk it's checking for                                 |
| -------------- | ------------------------------------------------------ |
| `alg`          | `alg=none` and other insecure algorithm configurations |
| `kid`          | Key-lookup injection attack surface                    |
| `jku` / `x5u`  | Untrusted external key/certificate references          |
| `jwk`          | Embedded public keys accepted at face value            |
| `crit`         | Unrecognized critical extension usage                  |
| `typ` / `cty`  | Type inconsistency, nested-JWT indicators              |
| `exp`          | Tokens that never expire                               |
| `aud` / `iss`  | Missing audience or issuer validation                  |
| `iat`          | No way to track token age                              |
| HMAC secret    | Weak/guessable HS256/384/512 signing keys              |

[IF YOU ALSO FLAG ALGORITHM CONFUSION (RS256 to HS256), ADD A ROW FOR IT. IF NOT, DON'T MENTION IT ANYWHERE.]

## How it works

1. Decode the token's structure (header, payload, signature)
2. Run the JOSE header audit
3. Run the security-relevant claim checks
4. Aggregate everything into severity-ranked findings
5. Optionally attempt HMAC secret recovery
6. Print a readable findings report

## Design decisions & trade-offs

A few choices in here were deliberate, so I'm writing down the reasoning instead of leaving it implicit.

### Why zero dependencies?

I stuck to Python's standard library only, for three reasons:

- It just works. No `pip install` step, no waiting on a CI runner, no dependency conflicts.
- No supply chain risk from pulling in third-party packages.
- It behaves the same on any system you drop it on.

The cost is that I had to handle base64 padding manually and write my own JWT decoding instead of importing something like PyJWT. It's worth it, because this tool is meant to run in places like CI runners, throwaway containers and bug bounty VMs, where `pip install` is sometimes blocked, slow, or not worth the hassle for a quick check.

### Why stream the wordlist instead of loading it all at once?

The wordlist loader yields lines one at a time instead of reading the whole file into memory. That matters once you point it at something like `rockyou.txt`, which has 10M+ lines, on a low-memory box. Loading it all up front would crash. The built-in list stays small on purpose. If you want real firepower, pass in your own with `--wordlist`.

### Constant-time comparison for the signature check

I used `hmac.compare_digest()` instead of a plain `==`. A regular string comparison stops at the first mismatched byte, which in theory leaks timing information an attacker could use to guess a secret one character at a time. It doesn't really matter for my own offline cracking loop, but it's the correct pattern, and I wanted the code to model it properly, since it's exactly the mistake to look for in a server's real auth check.

### Why no RS256 cracking?

HS256/384/512 use a shared secret, so brute-forcing it is at least theoretically possible. RS256 and ES256 use a private key, and brute-forcing that is out of reach with current hardware, so there's no point pretending to support it. J.A.W.S. checks the `alg` field and skips the cracking step automatically for anything starting with `RS` or `ES`.

### What I'd change if I rebuilt this

- A plugin system for custom checks, since JWT claims are app-specific and a one-size-fits-all checklist only goes so far
- JWK and JWE support
- Parallelized wordlist cracking, since it's single-threaded and slower than it needs to be

## Project structure

```
JWT-Analysis-Weakness-Scanner/
├── src/jaws/               # The package (CLI entry point: jaws.cli:main)
├── tests/                  # pytest suite
├── .github/workflows/      # CI
├── pyproject.toml          # Packaging; installs the `jaws` command
├── requirements.txt        # Dev/test dependencies only
├── LICENSE                 # MIT
└── README.md
```

The test suite uses `pytest`. To run it:

```
python3 -m pytest
```

## Limitations by design

This is a recon and analysis tool, not an exploitation framework. It intentionally does **not**:

- Automatically exploit anything it finds
- Attack remote systems
- Bypass authentication on its own
- Replace a thorough manual pentest

Treat its output as a starting point, and always verify findings manually against the actual target.

## Legal

Intended for authorized penetration testing, bug bounty programs, security research and learning. Only run it against systems you own or have explicit permission to test.

## Contributing

Bug reports and ideas are welcome. Open an issue, or send a pull request for anything on the "what I'd change" list above.

## License

MIT. See [LICENSE](LICENSE).

---

If this is useful to you, a star on the repo is appreciated.
