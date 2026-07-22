# 🦈 J.A.W.S — JWT Analysis & Weakness Scanner

[![](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![](https://img.shields.io/badge/dependencies-none-brightgreen)]()

**J.A.W.S (JWT Analysis & Weakness Scanner)** is a lightweight command-line security tool designed for **API security testing, bug bounty reconnaissance, and JWT security assessments**.

It analyzes JSON Web Tokens (JWTs), identifies common security weaknesses, and optionally tests HMAC signing secrets against a wordlist.

Built with Python's standard library only — **no external dependencies required**.

---

## ✨ Features

### 🔍 JWT Security Analysis

J.A.W.S performs automated checks for common JWT security issues:

- Algorithm misconfiguration (`alg=none`)
- Algorithm confusion risks (RS256 → HS256)
- Missing or invalid security claims (`exp`, `iat`, `nbf`, `iss`, `aud`, `sub`, `jti`)
- Weak token lifetime settings
- Suspicious JOSE headers
- Potential key management issues

### 🔐 JOSE Header Analysis

The scanner checks for:

| Header | Purpose |
| ------ | ------- |
| `alg`  | Detect insecure algorithm configurations |
| `typ`  | Check JWT type consistency (RFC 8725) |
| `kid`  | Identify potential key lookup risks (path traversal, SQLi) |
| `jku`  | Detect external key references (SSRF risks) |
| `x5u`  | Detect certificate URL references |
| `jwk`  | Detect embedded public keys |
| `crit` | Identify critical extension usage |
| `cty`  | Detect nested JWT indicators |

### 🔓 HMAC Secret Testing

For HMAC-signed JWTs, J.A.W.S can test whether weak signing secrets are being used.

**Supported algorithms:**
- HS256
- HS384
- HS512

**Features:**
- Custom wordlist support
- Built-in common secret list
- Streaming wordlist processing (memory-safe for `rockyou.txt`)
- Timeout protection (`--timeout`)
- Constant-time signature comparison (prevents timing attacks)

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/MuizRecon/JWT-Analysis-Weakness-Scanner.git
Navigate into the project:

bash
cd JWT-Analysis-Weakness-Scanner
No installation required. J.A.W.S uses only Python standard libraries.

Requirements:

Python 3.10+ (works with 3.6+)

⚡ Usage
Analyze a JWT
bash
python3 jaws.py <JWT_TOKEN>
Example:

bash
python3 jaws.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Analyze JWT from a file
bash
python3 jaws.py --file token.txt
Test HMAC secret strength
Using the built-in weak secret list:

bash
python3 jaws.py <JWT_TOKEN>
Using a custom wordlist:

bash
python3 jaws.py <JWT_TOKEN> --wordlist secrets.txt
Disable colored output
Useful for logs and automation:

bash
python3 jaws.py <JWT_TOKEN> --no-color
Skip secret testing
bash
python3 jaws.py <JWT_TOKEN> --no-crack
Set a timeout for cracking
bash
python3 jaws.py <JWT_TOKEN> --wordlist huge.txt --timeout 30
Full command options
bash
python3 jaws.py --help
text
usage: jaws.py [-h] [--file FILE] [--wordlist WORDLIST] [--no-crack] [--no-color] [--timeout TIMEOUT] [token]

J.A.W.S. — JWT Analysis & Weakness Scanner. A recon tool for bug bounty / API security testing.

positional arguments:
  token                The JWT string to analyze

options:
  -h, --help           show this help message and exit
  --file FILE          Path to a file containing the JWT (first line used)
  --wordlist WORDLIST  Path to a wordlist file for HMAC secret cracking
  --no-crack           Skip the secret-cracking step entirely
  --no-color           Disable colored/animated output
  --timeout TIMEOUT    Timeout for secret cracking in seconds (default: 60)
📊 Example Output
text
        _   ___        __/^\/^\/^\_______
       | | / \ \      /  ^          ^   \_
    _  | |/ A \ \    | J.A.W.S.           |
   | |_/ / W \_\_\    \___  ______________/
   |  _/ /  S  \_\        \/
   |_|/__/     \__\  JWT Analysis & Weakness Scanner

  Decode. Detect. Devour weak tokens.

──────────────────────────────────────────────────────────────────────
 DECODED TOKEN
──────────────────────────────────────────────────────────────────────

  Header:
   {
     "alg": "HS256",
     "typ": "JWT"
   }

  Payload:
   {
     "sub": "1234567890",
     "name": "John Doe",
     "iat": 1516239022
   }

──────────────────────────────────────────────────────────────────────
 SECRET CRACKING
──────────────────────────────────────────────────────────────────────

  Candidates tried: 4
  ✗ SECRET RECOVERED: 'your-256-bit-secret'

──────────────────────────────────────────────────────────────────────
 FINDINGS
──────────────────────────────────────────────────────────────────────

  1.  CRITICAL  Weak HMAC secret cracked
     Detail:         The signing secret was recovered: 'your-256-bit-secret'. This means anyone can forge arbitrary valid tokens (privilege escalation, account takeover, full auth bypass).
     Recommendation: Report immediately with high severity. Include the forging PoC and recommend rotating to a long, random, high-entropy secret plus rate-limiting/monitoring for auth anomalies.

  2.  MEDIUM  No 'exp' (expiration) claim
     Detail:         This token has no expiration, meaning it may be valid forever once issued.
     Recommendation: Confirm the server actually enforces its own session expiry elsewhere. If not, a leaked/stolen token never becomes invalid.

  3.  LOW  No 'iss' (issuer) claim
     Detail:         Missing issuer makes it harder to validate token origin.
     Recommendation: If the server enforces iss, test for misconfigurations.

  4.  LOW  No 'aud' (audience) claim
     Detail:         Missing audience claim means token might be valid across multiple services.
     Recommendation: Test for cross-service token reuse.

  5.  INFO  No 'jti' (JWT ID) claim
     Detail:         Missing unique identifier makes replay detection harder.
     Recommendation: If the server doesn't check jti, tokens may be replayable.

══════════════════════════════════════════════════════════════════════
 🦈  CRITICAL EXPOSURE — this token is forgeable/bypassable
 CRITICAL: 1   MEDIUM: 1   LOW: 2   INFO: 1
══════════════════════════════════════════════════════════════════════
🛡️ Security Checks
Vulnerability	Severity	Description
alg=none	CRITICAL	Detect unsigned JWT configurations
Weak HMAC secret	CRITICAL	Identify easily guessable signing keys
Empty HMAC secret	CRITICAL	Detect tokens signed with an empty key
Algorithm confusion	HIGH	Detect risky asymmetric → symmetric transitions
crit header	HIGH	Critical extensions that must be understood
Missing exp	MEDIUM	Tokens without expiration
External key references	MEDIUM	jku/x5u SSRF and key injection risks
Embedded JWK	MEDIUM	Trusted public key in header
Missing aud	LOW	Missing audience validation
Missing iss	LOW	Missing issuer validation
Missing iat	LOW	Token age tracking issues
kid header	INFO	Key lookup attack surface
Missing sub	INFO	Subject identifier missing
Missing jti	INFO	Replay detection weakened
Invalid claim types	INFO	JWT spec violations
Long token lifetime	LOW	Extended attack window
🏗️ Project Structure
text
JWT-Analysis-Weakness-Scanner/
│
├── jaws.py              # Main scanner (400+ lines)
├── README.md            # This documentation
├── LICENSE              # MIT License
├── .gitignore           # Ignore Python cache files
└── requirements.txt     # No external dependencies

🧪 Tested On
✅ Windows 10/11 (Python 3.10+)

✅ Kali Linux (Python 3.11)

✅ macOS (Python 3.9+)

✅ Ubuntu 20.04/22.04

🔬 Methodology
J.A.W.S follows a defensive JWT assessment workflow:

Decode — Parse JWT structure (header, payload, signature)

Analyze — Inspect JOSE headers for misconfigurations

Inspect — Validate security claims (exp, iat, nbf, iss, aud, sub, jti)

Test — Attempt HMAC secret cracking (optional)

Report — Generate a professional security assessment

⚠️ Limitations
J.A.W.S is an analysis and reconnaissance tool.

It does NOT:

Exploit vulnerabilities automatically

Attack remote systems

Bypass authentication by itself

Replace manual penetration testing

Findings should always be verified against authorized targets.

⚖️ Legal Disclaimer
This tool is created for:

Authorized penetration testing

Bug bounty programs

Security research

Educational environments

Only use J.A.W.S against systems you own or have explicit permission to test.

Unauthorized testing may be illegal. The author assumes no responsibility for misuse.

👨‍💻 Author
Abdulmuiz Adelabu (MuizRecon)

Cybersecurity Researcher

Focus areas:

API Security

JWT Security

Bug Bounty Hunting

Web Application Security

GitHub: github.com/MuizRecon

⭐ Future Improvements
Planned features:

□ JSON report export (--json)
□ JWT verification mode (--verify)
□ Public key analysis (RSA/ECDSA)
□ Additional claim checks (custom claims)
□ CI/CD integration (GitHub Actions)
□ Automated security scoring (0-100)
□ Parallel wordlist cracking (multiprocessing)
🙏 Contributing
Issues and pull requests are welcome!

Fork the repository

Create your feature branch (git checkout -b feature/amazing)

Commit your changes (git commit -m 'Add some amazing feature')

Push to the branch (git push origin feature/amazing)

Open a Pull Request

📄 License
This project is licensed under the MIT License — see the LICENSE file for details.

If you find this project useful, consider giving it a ⭐ on GitHub!

Made with ❤️ by MuizRecon
