"""Rule: WEAK_KEY.

Triggers when the certificate public key strength is below modern recommendations:
- RSA key size < 2048 bits
- EC key size < 256 bits
"""

from typing import Optional
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.severity import Confidence, Severity


class WeakKeyRule:
    def evaluate(self, profile: SecurityProfile, finding_id: str) -> Optional[Finding]:
        if not profile.certificate or profile.certificate.visibility != "OBSERVED":
            return None

        key_type = (profile.certificate.key_type or "").upper()
        key_size = profile.certificate.key_size

        if not key_size:
            return None

        is_weak = False
        reason = ""

        if "RSA" in key_type and key_size < 2048:
            is_weak = True
            reason = f"RSA key size of {key_size} bits is below the 2048-bit minimum recommendation."
        elif ("EC" in key_type or "ECDSA" in key_type) and key_size < 256:
            is_weak = True
            reason = f"Elliptic Curve key size of {key_size} bits is below the 256-bit recommendation."

        if is_weak:
            evidence = {
                "key_type": profile.certificate.key_type,
                "key_size": key_size,
                "subject": profile.certificate.subject,
                "tcp_stream": profile.tcp_stream,
            }
            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="WEAK_KEY",
                severity=Severity.MEDIUM,
                title="Weak public key size",
                description=reason,
                confidence=Confidence.OBSERVED,
                evidence=evidence,
            )
        return None
