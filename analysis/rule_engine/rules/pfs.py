"""Rule: PFS (Perfect Forward Secrecy).

Evaluates whether the negotiated TLS session provides forward secrecy.
- PFS = YES -> finding_type: PFS, severity: INFO
- PFS = NO  -> finding_type: PFS, severity: MEDIUM
- PFS = UNKNOWN -> None (do not guess)
"""

from typing import Optional
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.severity import Confidence, Severity


class PFSRule:
    def evaluate(self, profile: SecurityProfile, finding_id: str) -> Optional[Finding]:
        if not profile.tls or not profile.tls.version:
            return None

        pfs_status = profile.tls.pfs
        if pfs_status == "YES":
            confidence = (
                Confidence.INFERRED
                if profile.tls.version == "TLS 1.3"
                else Confidence.OBSERVED
            )
            version_desc = profile.tls.version
            if profile.tls.cipher_suite and "TLS 1.2" in profile.tls.version:
                desc = f"The negotiated {version_desc} cipher suite provides forward secrecy."
            else:
                desc = f"The {version_desc} session provides forward secrecy."

            evidence = {
                "tls_version": profile.tls.version,
                "cipher_suite": profile.tls.cipher_suite,
                "pfs": "YES",
            }
            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="PFS",
                severity=Severity.INFO,
                title="Forward secrecy was observed",
                description=desc,
                confidence=confidence,
                evidence=evidence,
            )
        elif pfs_status == "NO":
            evidence = {
                "tls_version": profile.tls.version,
                "cipher_suite": profile.tls.cipher_suite,
                "pfs": "NO",
            }
            return Finding(
                finding_id=finding_id,
                session_id=profile.session_id,
                finding_type="PFS",
                severity=Severity.MEDIUM,
                title="Forward secrecy not provided",
                description="The negotiated cipher suite does not provide perfect forward secrecy.",
                confidence=Confidence.OBSERVED,
                evidence=evidence,
            )

        return None
