"""JWT security auditing and weakness detection."""

import time
from typing import List, Dict, Any
from .models import Finding, Severity, DecodedToken


class JWTAuditor:
    """Audits a JWT against a checklist of common weaknesses."""

    def __init__(self):
        self.findings: List[Finding] = []

    def audit(self, token: DecodedToken) -> List[Finding]:
        """Run all checks against a decoded token."""
        self.findings = []

        self._check_header(token.header)
        self._check_claims(token.payload)

        return self.findings

    def _check_header(self, header: Dict[str, Any]) -> None:
        """JOSE header security checks."""
        if header.get('alg', '').lower() == 'none':
            self.findings.append(Finding(
                severity=Severity.CRITICAL,
                title='alg=none vulnerability',
                detail='The token accepts the "none" algorithm, allowing forged tokens.',
                recommendation='Disable "none" algorithm in JWT validation.',
                field='alg'
            ))

        weak_algs = ['HS256']
        if header.get('alg') in weak_algs:
            self.findings.append(Finding(
                severity=Severity.MEDIUM,
                title='Symmetric algorithm in use',
                detail=f'Using {header.get("alg")} means the same secret signs and verifies.',
                recommendation='Consider RS256 or ES256 for production systems.',
                field='alg'
            ))

        if 'kid' in header:
            self.findings.append(Finding(
                severity=Severity.MEDIUM,
                title='kid parameter present',
                detail='Key ID can be used for path traversal or SQL injection if not sanitized.',
                recommendation='Validate and sanitize kid values before filesystem/database lookup.',
                field='kid'
            ))

        if 'jku' in header:
            self.findings.append(Finding(
                severity=Severity.HIGH,
                title='jku (JWK Set URL) present',
                detail='Token references an external JWK Set URL which could be malicious.',
                recommendation='Only allow trusted jku endpoints, or disable jku validation.',
                field='jku'
            ))

        if 'x5u' in header:
            self.findings.append(Finding(
                severity=Severity.HIGH,
                title='x5u (X.509 URL) present',
                detail='Token references an external certificate URL.',
                recommendation='Validate certificate URLs against a whitelist.',
                field='x5u'
            ))

        if 'jwk' in header:
            self.findings.append(Finding(
                severity=Severity.HIGH,
                title='jwk (Embedded Key) present',
                detail='Token contains an embedded public key accepted at face value.',
                recommendation='Do not accept jwk without additional validation.',
                field='jwk'
            ))

        if 'crit' in header:
            self.findings.append(Finding(
                severity=Severity.MEDIUM,
                title='crit (Critical extensions) present',
                detail='Token contains critical extensions that must be understood.',
                recommendation='Ensure your JWT library handles all critical extensions.',
                field='crit'
            ))

        if header.get('cty') == 'JWT':
            self.findings.append(Finding(
                severity=Severity.LOW,
                title='cty=JWT (nested JWT)',
                detail='This token may contain a nested JWT.',
                recommendation='Verify nested token handling is secure.',
                field='cty'
            ))

    def _check_claims(self, payload: Dict[str, Any]) -> None:
        """Claim-level security checks."""
        now = int(time.time())

        if 'exp' not in payload:
            self.findings.append(Finding(
                severity=Severity.HIGH,
                title='Missing expiration (exp) claim',
                detail='Token never expires, making it valid indefinitely.',
                recommendation='Always include exp with a reasonable lifetime.',
                field='exp'
            ))
        else:
            exp = payload.get('exp')
            if isinstance(exp, int) and exp < now:
                self.findings.append(Finding(
                    severity=Severity.INFO,
                    title='Token expired',
                    detail=f'Token expired at {time.ctime(exp)}.',
                    recommendation='Request a new token.',
                    field='exp'
                ))
            elif isinstance(exp, int) and exp - now < 300:
                self.findings.append(Finding(
                    severity=Severity.LOW,
                    title='Token expiring soon',
                    detail=f'Token expires in less than 5 minutes.',
                    recommendation='Refresh the token soon.',
                    field='exp'
                ))

        if 'aud' not in payload:
            self.findings.append(Finding(
                severity=Severity.MEDIUM,
                title='Missing audience (aud) claim',
                detail='No audience restriction, token may be used across services.',
                recommendation='Define aud to restrict token usage.',
                field='aud'
            ))

        if 'iss' not in payload:
            self.findings.append(Finding(
                severity=Severity.LOW,
                title='Missing issuer (iss) claim',
                detail='No issuer specified, origin cannot be verified.',
                recommendation='Include iss to establish trust.',
                field='iss'
            ))

        if 'iat' not in payload:
            self.findings.append(Finding(
                severity=Severity.LOW,
                title='Missing issued-at (iat) claim',
                detail='Token age cannot be tracked.',
                recommendation='Include iat to support token age policies.',
                field='iat'
            ))
