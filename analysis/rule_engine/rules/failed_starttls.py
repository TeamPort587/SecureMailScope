"""Rule: FAILED_STARTTLS.

Triggers when STARTTLS was advertised by the server, but the session failed to
complete a successful TLS upgrade.
"""

from typing import Optional
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.severity import Confidence, Severity


class FailedSTARTTLSRule:
    def evaluate(self, profile: SecurityProfile, finding_id: str) -> Optional[Finding]:
        sec = profile.security
        if sec.upgrade_requested == "YES" and sec.upgrade_succeeded == "NO":
            evidence = {
                "upgrade_advertised": sec.upgrade_advertised,
                "upgrade_requested": sec.upgrade_requested,
                "upgrade_succeeded": sec.upgrade_succeeded,
            }
            if profile.tcp_stream:
                evidence["tcp_stream"] = profile.tcp_stream

            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="FAILED_STARTTLS",
                severity=Severity.HIGH,
                title="STARTTLS was advertised but not completed",
                description="The server advertised STARTTLS but the session did not successfully upgrade to TLS.",
                confidence=Confidence.OBSERVED,
                evidence=evidence,
            )
        return None
