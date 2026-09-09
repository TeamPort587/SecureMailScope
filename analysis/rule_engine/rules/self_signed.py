"""Rule: SELF_SIGNED.

Triggers when the certificate is self-signed (subject matches issuer).
"""

from typing import Optional
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.severity import Confidence, Severity


class SelfSignedCertificateRule:
    def evaluate(self, profile: SecurityProfile, finding_id: str) -> Optional[Finding]:
        if not profile.certificate or profile.certificate.visibility != "OBSERVED":
            return None

        if profile.certificate.self_signed is True:
            evidence = {
                "subject": profile.certificate.subject,
                "issuer": profile.certificate.issuer,
                "tcp_stream": profile.tcp_stream,
            }
            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="SELF_SIGNED",
                severity=Severity.LOW,
                title="Self-signed certificate",
                description="The certificate is self-signed (subject matches issuer), which lacks verification by a trusted Certificate Authority.",
                confidence=Confidence.OBSERVED,
                evidence=evidence,
            )
        return None
