"""Rule: AUTH_BEFORE_TLS.

Triggers when authentication commands or credentials are sent prior to establishing
a TLS encrypted channel.
"""

from typing import Optional
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.severity import Confidence, Severity


class AuthBeforeTLSRule:
    def evaluate(self, profile: SecurityProfile, finding_id: str = "finding-001") -> Optional[Finding]:
        if profile.security.authentication_before_tls == "YES":
            evidence = {
                "protocol": profile.protocol,
                "server_port": profile.server_port,
                "authentication_before_tls": True,
            }
            if profile.tcp_stream is not None:
                evidence["tcp_stream"] = profile.tcp_stream
                evidence["wireshark_filter"] = f"tcp.stream == {profile.tcp_stream}"
            if profile.frame_numbers:
                evidence["frame_numbers"] = profile.frame_numbers[:5]

            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="AUTH_BEFORE_TLS",
                severity=Severity.CRITICAL,
                title="Authentication occurred before TLS",
                description="Authentication-related traffic was observed before the STARTTLS upgrade.",
                confidence=Confidence.OBSERVED,
                evidence=evidence,
            )
        return None
