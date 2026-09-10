"""Rule: PLAINTEXT.

Triggers when an email session is conducted entirely in unencrypted plaintext.
"""

from typing import Optional
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.severity import Confidence, Severity


class PlaintextRule:
    def evaluate(self, profile: SecurityProfile, finding_id: str) -> Optional[Finding]:
        if profile.security.encryption_mode == "PLAINTEXT":
            evidence = {
                "protocol": profile.protocol,
                "server_port": profile.server_port,
                "encryption_mode": "PLAINTEXT",
            }
            if profile.tcp_stream:
                evidence["tcp_stream"] = profile.tcp_stream

            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="PLAINTEXT",
                severity=Severity.CRITICAL,
                title=f"{profile.protocol} session was transmitted in plaintext",
                description=f"The {profile.protocol} session did not use TLS protection.",
                confidence=Confidence.OBSERVED,
                evidence=evidence,
            )
        return None
