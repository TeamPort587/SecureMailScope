"""Email Security Standards Profile (RFC 8314)."""

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

RFC_8314 = StandardsSource(
    name="RFC 8314",
    title="Cleartext Considered Obsolete: Use of Transport Layer Security (TLS) for Email Submission and Access",
    section="Section 3 (Cleartext Obsolete) & Section 4.1 / 5.1 (Implicit TLS Recommendation)",
    url="https://datatracker.ietf.org/doc/html/rfc8314",
    published_date="2018-05",
    effective_status="CURRENT",
)


class EmailSecurityProfile(BaseStandardsProfile):
    """Evaluates email session transport security against RFC 8314."""

    @property
    def profile_info(self) -> StandardsProfile:
        return StandardsProfile(
            id="email-security",
            name="Email Security (RFC 8314)",
            version="2024.1",
            description="Guidance on obsolete cleartext and preference for Implicit TLS on dedicated ports per RFC 8314.",
            last_reviewed="2026-01-15",
            sources=[RFC_8314],
        )

    def evaluate(self, session: SecurityProfile) -> List[ComparisonResult]:
        results: List[ComparisonResult] = []

        enc_result = self._evaluate_encryption_mode(session)
        if enc_result:
            results.append(enc_result)

        return results

    def _evaluate_encryption_mode(self, session: SecurityProfile) -> Optional[ComparisonResult]:
        options = [
            StandardsOption(
                value="PLAINTEXT",
                label="Cleartext / Plaintext",
                status=StandardsStatus.DEPRECATED,
                description="Obsolete. Unencrypted email transmission exposes credentials and contents to passive eavesdropping.",
            ),
            StandardsOption(
                value="STARTTLS",
                label="STARTTLS (Opportunistic)",
                status=StandardsStatus.ACCEPTABLE,
                description="Acceptable upgrade on submission/access ports, but susceptible to active MITM stripping attacks.",
            ),
            StandardsOption(
                value="IMPLICIT_TLS",
                label="Implicit TLS (Dedicated Port)",
                status=StandardsStatus.PREFERRED,
                description="Preferred by RFC 8314; TLS begins immediately at TCP connection, preventing stripping attacks.",
            ),
        ]

        mode = session.security.encryption_mode
        port = session.server_port
        proto = session.protocol

        if mode == "IMPLICIT_TLS":
            status = StandardsStatus.PREFERRED
            observed = "Implicit TLS (Direct TLS)"
            rationale = (
                f"The session utilized Implicit TLS (direct TLS on port {port}). "
                "RFC 8314 Section 4.1 & 5.1 explicitly prefers Implicit TLS over STARTTLS for mail submission and access "
                "because it eliminates STARTTLS-stripping vulnerabilities entirely."
            )
        elif mode == "STARTTLS":
            status = StandardsStatus.ACCEPTABLE
            observed = "STARTTLS (In-Band Upgrade)"
            rationale = (
                f"The session negotiated TLS via the STARTTLS upgrade command on port {port}. "
                "While acceptable and widely deployed, RFC 8314 Section 4.1 prefers Implicit TLS (ports 465, 993, 995) "
                "for submission and access to avoid active protocol-downgrade attacks."
            )
        elif mode == "PLAINTEXT":
            status = StandardsStatus.DEPRECATED
            observed = "Plaintext (Cleartext)"
            rationale = (
                f"The {proto} session operated completely in cleartext. "
                "RFC 8314 Section 3 declares cleartext email submission and access obsolete, "
                "as it exposes sensitive authentication credentials and email content."
            )
        else:
            status = StandardsStatus.UNKNOWN
            observed = "Unknown / Indeterminate"
            rationale = "Passive analysis could not unambiguously determine the transport encryption mode."

        return ComparisonResult(
            field="email_encryption_mode",
            label="Email Transport Encryption Mode",
            observed=observed,
            status=status,
            preferred=["Implicit TLS (Dedicated Port)"],
            visualization=VisualizationType.ORDERED_SPECTRUM,
            options=options,
            profile="email-security",
            profile_name="Email Security (RFC 8314)",
            rationale=rationale,
            sources=[RFC_8314],
        )
