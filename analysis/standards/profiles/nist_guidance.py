"""NIST TLS Guidance & Key Management Profile (NIST SP 800-52 Rev. 2 & SP 800-57 Part 1)."""

from datetime import datetime, timezone
from typing import List, Optional
from analysis.feature_extraction.models import SecurityProfile
from analysis.standards.models import (
    ComparisonResult,
    StandardsOption,
    StandardsSource,
    StandardsStatus,
    VisualizationType,
    StandardsProfile,
)
from analysis.standards.profiles.base import BaseStandardsProfile

NIST_SP800_52 = StandardsSource(
    name="NIST SP 800-52 Rev. 2",
    title="Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations",
    section="Section 3.1 (Protocol Versions) & Section 3.3 (Certificate Key Strengths)",
    url="https://csrc.nist.gov/pubs/sp/800/52/r2/final",
    published_date="2019-08",
    effective_status="SUBJECT_TO_PERIODIC_REVIEW",
)

NIST_SP800_57 = StandardsSource(
    name="NIST SP 800-57 Part 1 Rev. 5",
    title="Recommendation for Key Management: Part 1 – General",
    section="Table 2: Comparable security strengths of symmetric and asymmetric algorithms",
    url="https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
    published_date="2020-05",
    effective_status="CURRENT",
)


def _parse_iso(iso_str: Optional[str]) -> Optional[datetime]:
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


class NISTGuidanceProfile(BaseStandardsProfile):
    """Evaluates certificate key strength and validity against NIST guidelines."""

    @property
    def profile_info(self) -> StandardsProfile:
        return StandardsProfile(
            id="nist-tls-guidance",
            name="NIST TLS & Key Management Guidance",
            version="SP800-Rev2",
            description="Cryptographic algorithm and key strength guidelines from NIST SP 800-52 Rev. 2 and SP 800-57.",
            last_reviewed="2026-01-15",
            sources=[NIST_SP800_52, NIST_SP800_57],
        )

    def evaluate(self, session: SecurityProfile) -> List[ComparisonResult]:
        results: List[ComparisonResult] = []

        # Only evaluate certificate if TLS was present or attempted
        if session.security.encryption_mode == "PLAINTEXT":
            return results

        cert = session.certificate
        if not cert:
            return results

        # 1. Key Strength Comparison
        res_key = self._evaluate_key_strength(session)
        if res_key:
            results.append(res_key)

        # 2. Certificate Validity Assessment
        res_val = self._evaluate_certificate_validity(session)
        if res_val:
            results.append(res_val)

        return results

    def _evaluate_key_strength(self, session: SecurityProfile) -> Optional[ComparisonResult]:
        cert = session.certificate
        if not cert:
            return None

        # Passive capture epistemological check: TLS 1.3 encrypted cert
        if cert.visibility == "NOT_OBSERVABLE":
            return ComparisonResult(
                field="certificate_key_strength",
                label="Certificate Key Strength",
                observed="Not Observable (Encrypted in TLS 1.3)",
                status=StandardsStatus.NOT_OBSERVABLE,
                preferred=["RSA 3072 / 4096-bit", "EC P-256 / P-384"],
                visualization=VisualizationType.STATUS_ASSESSMENT,
                options=[],
                profile="nist-tls-guidance",
                profile_name="NIST Guidance (SP 800-52 Rev. 2 / SP 800-57)",
                rationale="In TLS 1.3, the server certificate message is encrypted in flight. Passive network inspection cannot inspect the public key algorithm without session decryption keys. This is an expected privacy property of TLS 1.3.",
                sources=[NIST_SP800_52, NIST_SP800_57],
            )

        key_type = (cert.key_type or "RSA").upper()
        key_size = cert.key_size or 2048

        options = [
            StandardsOption(
                value="RSA_UNDER_2048",
                label="RSA < 2048-bit",
                status=StandardsStatus.DEPRECATED,
                description="Legacy / Obsolete. Disallowed by NIST SP 800-57 after 2013 due to insufficient factoring resistance.",
            ),
            StandardsOption(
                value="RSA_2048",
                label="RSA 2048-bit",
                status=StandardsStatus.ACCEPTABLE,
                description="112-bit security strength; acceptable under NIST SP 800-52 Rev. 2 through 2030.",
            ),
            StandardsOption(
                value="RSA_3072_PLUS",
                label="RSA >= 3072-bit / EC P-256+",
                status=StandardsStatus.PREFERRED,
                description="128-bit+ security strength; preferred for modern infrastructure and post-2030 longevity.",
            ),
        ]

        if key_type in ("EC", "ECDSA"):
            if key_size >= 256:
                status = StandardsStatus.PREFERRED
                observed = f"EC {key_size}-bit (ECDSA)"
                rationale = f"Elliptic-curve key of {key_size} bits provides >= 128-bit security strength, equivalent to RSA-3072+. Preferred under NIST SP 800-52 Rev. 2 Section 3.3."
            else:
                status = StandardsStatus.NOT_RECOMMENDED
                observed = f"EC {key_size}-bit (ECDSA)"
                rationale = f"Elliptic-curve key below 256 bits ({key_size} bits) does not satisfy the 128-bit minimum security strength."
        elif key_type == "RSA":
            if key_size < 2048:
                status = StandardsStatus.DEPRECATED
                observed = f"RSA {key_size}-bit"
                rationale = f"RSA keys smaller than 2048 bits ({key_size} bits) provide less than 112 bits of security and were disallowed by NIST SP 800-57 after 2013."
            elif key_size == 2048:
                status = StandardsStatus.ACCEPTABLE
                observed = "RSA 2048-bit"
                rationale = "RSA 2048-bit provides 112-bit security strength, which is acceptable through 2030 under NIST SP 800-52 Rev. 2. RSA-3072+ or EC P-256 is preferred for greater longevity."
            else:
                status = StandardsStatus.PREFERRED
                observed = f"RSA {key_size}-bit"
                rationale = f"RSA {key_size}-bit provides >= 128-bit security strength, aligning with NIST SP 800-57 recommendations for long-term protection."
        else:
            status = StandardsStatus.ACCEPTABLE
            observed = f"{key_type} {key_size}-bit"
            rationale = f"Observed key algorithm ({key_type}) with {key_size}-bit key size."

        return ComparisonResult(
            field="certificate_key_strength",
            label="Certificate Key Strength",
            observed=observed,
            status=status,
            preferred=["RSA >= 3072-bit / EC P-256+"],
            visualization=VisualizationType.ORDERED_SPECTRUM,
            options=options,
            profile="nist-tls-guidance",
            profile_name="NIST Guidance (SP 800-52 Rev. 2 / SP 800-57)",
            rationale=rationale,
            sources=[NIST_SP800_52, NIST_SP800_57],
        )

    def _evaluate_certificate_validity(self, session: SecurityProfile) -> Optional[ComparisonResult]:
        cert = session.certificate
        if not cert:
            return None

        if cert.visibility == "NOT_OBSERVABLE":
            return ComparisonResult(
                field="certificate_validity",
                label="Certificate Validity Period",
                observed="Not Observable (Encrypted in TLS 1.3)",
                status=StandardsStatus.NOT_OBSERVABLE,
                preferred=["Valid at Session Timestamp"],
                visualization=VisualizationType.STATUS_ASSESSMENT,
                options=[],
                profile="nist-tls-guidance",
                profile_name="NIST Guidance (SP 800-52 Rev. 2)",
                rationale="Certificate validity period cannot be established because TLS 1.3 encrypts certificate metadata in flight.",
                sources=[NIST_SP800_52],
            )

        ref_time = session.capture_reference_time
        if ref_time is None and session.start_time:
            ref_time = _parse_iso(session.start_time)
        if ref_time is None:
            ref_time = datetime.now(timezone.utc)

        valid_from_dt = _parse_iso(cert.valid_from)
        valid_until_dt = _parse_iso(cert.valid_until)

        options = [
            StandardsOption(
                value="NOT_YET_VALID",
                label="Not Yet Valid",
                status=StandardsStatus.NOT_RECOMMENDED,
                description="Session capture timestamp preceded the certificate notBefore date.",
            ),
            StandardsOption(
                value="VALID_DURING_CAPTURE",
                label="Valid During Capture",
                status=StandardsStatus.RECOMMENDED,
                description="Session capture timestamp is within the certificate validity window [notBefore, notAfter].",
            ),
            StandardsOption(
                value="EXPIRED_AT_CAPTURE",
                label="Expired at Capture",
                status=StandardsStatus.DEPRECATED,
                description="Session capture timestamp succeeded the certificate notAfter expiration date.",
            ),
        ]

        if valid_until_dt and valid_until_dt < ref_time:
            status = StandardsStatus.DEPRECATED
            observed = f"Expired at Capture Time ({cert.valid_until})"
            rationale = f"The certificate validity period ended on {cert.valid_until}, which preceded the session capture time ({ref_time.isoformat()}). Expired certificates fail authentication under NIST SP 800-52 Rev. 2 Section 3.1."
        elif valid_from_dt and valid_from_dt > ref_time:
            status = StandardsStatus.NOT_RECOMMENDED
            observed = f"Not Yet Valid at Capture Time ({cert.valid_from})"
            rationale = f"The certificate valid_from date ({cert.valid_from}) was after the session capture time ({ref_time.isoformat()})."
        elif valid_from_dt and valid_until_dt:
            status = StandardsStatus.RECOMMENDED
            observed = "Valid During Session Capture"
            rationale = f"The certificate was valid when the session was recorded. Validity period spans {cert.valid_from[:10]} to {cert.valid_until[:10]}, covering capture time {ref_time.isoformat()[:10]}."
        else:
            status = StandardsStatus.UNKNOWN
            observed = "Validity Window Indeterminate"
            rationale = "Certificate timestamps could not be extracted from passive capture."

        return ComparisonResult(
            field="certificate_validity",
            label="Certificate Validity Period",
            observed=observed,
            status=status,
            preferred=["Valid During Capture"],
            visualization=VisualizationType.STATUS_ASSESSMENT,
            options=options,
            profile="nist-tls-guidance",
            profile_name="NIST Guidance (SP 800-52 Rev. 2)",
            rationale=rationale,
            sources=[NIST_SP800_52],
        )
