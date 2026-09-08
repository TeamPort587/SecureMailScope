"""Rule: WEAK_CIPHER.

Triggers when the negotiated cipher suite uses legacy or broken cryptography
(e.g., RC4, DES, 3DES, NULL, EXPORT, MD5).
"""

from typing import Optional
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.severity import Confidence, Severity

WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "Anon"]


class WeakCipherRule:
    def evaluate(self, profile: SecurityProfile, finding_id: str) -> Optional[Finding]:
        if not profile.tls or not profile.tls.cipher_suite:
            return None

        cipher = profile.tls.cipher_suite.upper()
        is_weak = any(kw.upper() in cipher for kw in WEAK_CIPHER_KEYWORDS)

        if is_weak:
            evidence = {
                "cipher_suite": profile.tls.cipher_suite,
                "tcp_stream": profile.tcp_stream,
            }
            if profile.frame_numbers:
                evidence["frame_numbers"] = profile.frame_numbers[:5]
            if profile.tls.version:
                evidence["tls_version"] = profile.tls.version

            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="WEAK_CIPHER",
                severity=Severity.CRITICAL,
                title="Weak cipher suite negotiated",
                description=f"A weak or legacy cipher suite ({profile.tls.cipher_suite}) was negotiated.",
                confidence=Confidence.OBSERVED,
                evidence=evidence,
            )
        return None
