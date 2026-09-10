"""Rule: EXPIRED_CERTIFICATE.

Triggers when the certificate valid_until timestamp precedes the capture reference time.
"""

from datetime import datetime, timezone
from typing import Optional
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.severity import Confidence, Severity


def _parse_iso(iso_str: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


class ExpiredCertificateRule:
    def evaluate(self, profile: SecurityProfile, finding_id: str) -> Optional[Finding]:
        if not profile.certificate or profile.certificate.visibility != "OBSERVED":
            return None
        if not profile.certificate.valid_until:
            return None

        valid_until_dt = _parse_iso(profile.certificate.valid_until)
        if not valid_until_dt:
            return None

        ref_time = profile.capture_reference_time or datetime.now(timezone.utc)
        if ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        if valid_until_dt < ref_time:
            evidence = {
                "valid_until": profile.certificate.valid_until,
                "reference_time": ref_time.isoformat(),
                "subject": profile.certificate.subject,
                "tcp_stream": profile.tcp_stream,
            }
            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="EXPIRED_CERTIFICATE",
                severity=Severity.HIGH,
                title="Expired X.509 certificate",
                description=f"The server certificate expired on {profile.certificate.valid_until} before the capture date.",
                confidence=Confidence.OBSERVED,
                evidence=evidence,
            )
        return None
