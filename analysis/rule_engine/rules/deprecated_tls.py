"""Rule: DEPRECATED_TLS.

Triggers when negotiated TLS is SSLv3, TLS 1.0, or TLS 1.1.
"""

from typing import Optional
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.severity import Confidence, Severity

DEPRECATED_VERSIONS = {"SSLv3", "TLS 1.0", "TLS 1.1"}


class DeprecatedTLSRule:
    def evaluate(self, profile: SecurityProfile, finding_id: str) -> Optional[Finding]:
        if not profile.tls or not profile.tls.version:
            return None

        version = profile.tls.version.strip()
        if version in DEPRECATED_VERSIONS:
            evidence = {
                "tls_version": version,
                "tcp_stream": profile.tcp_stream,
            }
            if profile.frame_numbers:
                evidence["frame_numbers"] = profile.frame_numbers[:5]
            if profile.tls.cipher_suite:
                evidence["cipher_suite"] = profile.tls.cipher_suite

            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="DEPRECATED_TLS",
                severity=Severity.HIGH,
                title=f"Deprecated TLS version negotiated ({version})",
                description=f"{version} was negotiated for the email session. This protocol version is obsolete and insecure.",
                confidence=Confidence.OBSERVED,
                evidence=evidence,
            )
        return None
