"""IETF Modern TLS Standards Profile (RFC 9325 & RFC 8996)."""

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

RFC_9325 = StandardsSource(
    name="RFC 9325",
    title="Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)",
    section="Section 3.1.1 (Protocol Versions) & Section 4.2 (Cipher Suites)",
    url="https://datatracker.ietf.org/doc/html/rfc9325",
    published_date="2022-11",
    effective_status="CURRENT",
)

RFC_8996 = StandardsSource(
    name="RFC 8996",
    title="Deprecating TLS 1.0 and TLS 1.1",
    section="Section 1 (Introduction & Formal Deprecation)",
    url="https://datatracker.ietf.org/doc/html/rfc8996",
    published_date="2021-03",
    effective_status="CURRENT",
)


class IETFModernTLSProfile(BaseStandardsProfile):
    """Evaluates TLS configuration against modern IETF guidance."""

    @property
    def profile_info(self) -> StandardsProfile:
        return StandardsProfile(
            id="ietf-modern-tls",
            name="IETF Modern TLS Guidance",
            version="2024.1",
            description="Best practices for TLS deployment defined in BCP 195 / RFC 9325 and RFC 8996.",
            last_reviewed="2026-01-15",
            sources=[RFC_9325, RFC_8996],
        )

    def evaluate(self, session: SecurityProfile) -> List[ComparisonResult]:
        results: List[ComparisonResult] = []

        is_plaintext = session.security.encryption_mode == "PLAINTEXT"
        has_tls = session.tls is not None and bool(session.tls.version)

        # 1. TLS Version Comparison
        res_version = self._evaluate_tls_version(session, is_plaintext, has_tls)
        if res_version:
            results.append(res_version)

        # 2. Cipher Suite Comparison
        if has_tls and session.tls and session.tls.cipher_suite:
            res_cipher = self._evaluate_cipher_suite(session)
            if res_cipher:
                results.append(res_cipher)

        # 3. Forward Secrecy (PFS) Comparison
        if has_tls and session.tls:
            res_pfs = self._evaluate_pfs(session)
            if res_pfs:
                results.append(res_pfs)

        return results

    def _evaluate_tls_version(
        self, session: SecurityProfile, is_plaintext: bool, has_tls: bool
    ) -> Optional[ComparisonResult]:
        options = [
            StandardsOption(
                value="TLS 1.0",
                label="TLS 1.0",
                status=StandardsStatus.DEPRECATED,
                description="Obsolete protocol with outdated cipher constructs (RFC 8996).",
            ),
            StandardsOption(
                value="TLS 1.1",
                label="TLS 1.1",
                status=StandardsStatus.DEPRECATED,
                description="Obsolete protocol with outdated cipher constructs (RFC 8996).",
            ),
            StandardsOption(
                value="TLS 1.2",
                label="TLS 1.2",
                status=StandardsStatus.ACCEPTABLE,
                description="Acceptable baseline under RFC 9325 when configured with AEAD ciphers and forward secrecy.",
            ),
            StandardsOption(
                value="TLS 1.3",
                label="TLS 1.3",
                status=StandardsStatus.PREFERRED,
                description="Preferred modern version offering 1-RTT handshakes and mandatory modern cryptography.",
            ),
        ]

        if is_plaintext:
            return ComparisonResult(
                field="tls_version",
                label="TLS Protocol Version",
                observed="PLAINTEXT (None)",
                status=StandardsStatus.DEPRECATED,
                preferred=["TLS 1.3"],
                visualization=VisualizationType.ORDERED_SPECTRUM,
                options=options,
                profile="ietf-modern-tls",
                profile_name="IETF Modern TLS (RFC 9325)",
                rationale="Unencrypted plaintext communication is obsolete. RFC 9325 and RFC 8314 require TLS for secure communication.",
                sources=[RFC_9325, RFC_8996],
            )

        if not has_tls or not session.tls or not session.tls.version:
            return ComparisonResult(
                field="tls_version",
                label="TLS Protocol Version",
                observed="UNKNOWN",
                status=StandardsStatus.UNKNOWN,
                preferred=["TLS 1.3"],
                visualization=VisualizationType.ORDERED_SPECTRUM,
                options=options,
                profile="ietf-modern-tls",
                profile_name="IETF Modern TLS (RFC 9325)",
                rationale="Insufficient handshake packets were observed to determine the negotiated TLS protocol version.",
                sources=[RFC_9325],
            )

        version = session.tls.version.strip()
        v_upper = version.upper()

        if "1.3" in v_upper:
            status = StandardsStatus.PREFERRED
            rationale = "TLS 1.3 is the preferred protocol version under RFC 9325, providing simplified modern cryptographic options and enhanced privacy."
        elif "1.2" in v_upper:
            status = StandardsStatus.ACCEPTABLE
            rationale = "TLS 1.2 is acceptable under RFC 9325 when configured with AEAD cipher suites and forward secrecy. TLS 1.3 is preferred for modern deployments."
        elif any(dep in v_upper for dep in ["1.0", "1.1", "SSL 3.0", "SSL 2.0", "SSLV"]):
            status = StandardsStatus.DEPRECATED
            rationale = f"{version} is formally deprecated by RFC 8996. It lacks support for current AEAD ciphers and is vulnerable to known protocol downgrade and chosen-plaintext attacks."
        else:
            status = StandardsStatus.UNKNOWN
            rationale = f"Observed version ({version}) is unclassified under current standard profiles."

        return ComparisonResult(
            field="tls_version",
            label="TLS Protocol Version",
            observed=version,
            status=status,
            preferred=["TLS 1.3"],
            visualization=VisualizationType.ORDERED_SPECTRUM,
            options=options,
            profile="ietf-modern-tls",
            profile_name="IETF Modern TLS (RFC 9325)",
            rationale=rationale,
            sources=[RFC_9325, RFC_8996],
        )

    def _evaluate_cipher_suite(self, session: SecurityProfile) -> Optional[ComparisonResult]:
        if not session.tls or not session.tls.cipher_suite:
            return None

        cipher = session.tls.cipher_suite
        c_upper = cipher.upper()

        options = [
            StandardsOption(
                value="LEGACY_INSECURE",
                label="Legacy / Insecure",
                status=StandardsStatus.DEPRECATED,
                description="Broken or weak ciphers: RC4, 3DES, DES, EXPORT, NULL.",
            ),
            StandardsOption(
                value="CBC_MODE",
                label="CBC Mode (Non-AEAD)",
                status=StandardsStatus.NOT_RECOMMENDED,
                description="AES-CBC suites susceptible to padding oracle and timing attacks (RFC 9325 Sec 4.2.2).",
            ),
            StandardsOption(
                value="AEAD_MODERN",
                label="AEAD (GCM / Poly1305)",
                status=StandardsStatus.PREFERRED,
                description="Authenticated Encryption with Associated Data (AES-GCM, ChaCha20-Poly1305) required by RFC 9325.",
            ),
        ]

        is_legacy = any(bad in c_upper for bad in ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"])
        is_aead = any(good in c_upper for good in ["GCM", "CHACHA20", "POLY1305", "CCM"])
        is_cbc = "CBC" in c_upper

        if is_legacy:
            status = StandardsStatus.DEPRECATED
            observed_cat = "Legacy / Insecure"
            rationale = f"The cipher suite ({cipher}) utilizes obsolete or broken cryptographic algorithms explicitly prohibited by RFC 9325 Section 4.2.1."
        elif is_aead:
            status = StandardsStatus.PREFERRED
            observed_cat = "AEAD (GCM / Poly1305)"
            rationale = f"The negotiated cipher suite ({cipher}) provides Authenticated Encryption with Associated Data (AEAD), satisfying RFC 9325 Section 4.2.1 recommendations."
        elif is_cbc:
            status = StandardsStatus.NOT_RECOMMENDED
            observed_cat = "CBC Mode (Non-AEAD)"
            rationale = f"The negotiated cipher suite ({cipher}) relies on CBC mode encryption. RFC 9325 Section 4.2.2 advises against CBC ciphers due to padding oracle attacks (e.g. Lucky13)."
        else:
            status = StandardsStatus.ACCEPTABLE
            observed_cat = "Non-AEAD Standard"
            rationale = f"The negotiated cipher suite ({cipher}) is functional but modern AEAD suites (AES-GCM or ChaCha20-Poly1305) are preferred."

        return ComparisonResult(
            field="cipher_suite",
            label="Cipher Suite Classification",
            observed=f"{cipher} ({observed_cat})",
            status=status,
            preferred=["AEAD (GCM / Poly1305)"],
            visualization=VisualizationType.CATEGORICAL_SPECTRUM,
            options=options,
            profile="ietf-modern-tls",
            profile_name="IETF Modern TLS (RFC 9325)",
            rationale=rationale,
            sources=[RFC_9325],
            metadata={"raw_cipher": cipher, "category": observed_cat},
        )

    def _evaluate_pfs(self, session: SecurityProfile) -> Optional[ComparisonResult]:
        if not session.tls:
            return None

        pfs_status = session.tls.pfs
        options = [
            StandardsOption(
                value="NO_PFS",
                label="No Forward Secrecy",
                status=StandardsStatus.NOT_RECOMMENDED,
                description="Static RSA key exchange; compromised server private key enables retroactive decryption.",
            ),
            StandardsOption(
                value="PFS",
                label="Forward Secrecy (PFS)",
                status=StandardsStatus.PREFERRED,
                description="Ephemeral key exchange (ECDHE / DHE); past session traffic cannot be retroactively decrypted.",
            ),
        ]

        if pfs_status == "YES":
            status = StandardsStatus.PREFERRED
            observed = "Forward Secrecy Observed (PFS)"
            rationale = "The session negotiated an ephemeral key exchange (e.g. ECDHE), ensuring forward secrecy as mandated by RFC 9325 Section 3.4.2."
        elif pfs_status == "NO":
            status = StandardsStatus.NOT_RECOMMENDED
            observed = "No Forward Secrecy"
            rationale = "The session does not provide perfect forward secrecy. RFC 9325 Section 3.4.2 mandates forward secrecy so that past traffic remains protected if the server certificate key is ever exposed."
        else:
            status = StandardsStatus.UNKNOWN
            observed = "Unknown / Incomplete Handshake"
            rationale = "Passive capture did not observe sufficient key exchange parameters to determine forward secrecy standing."

        return ComparisonResult(
            field="pfs",
            label="Forward Secrecy (PFS)",
            observed=observed,
            status=status,
            preferred=["Forward Secrecy (PFS)"],
            visualization=VisualizationType.CAPABILITY_COMPARISON,
            options=options,
            profile="ietf-modern-tls",
            profile_name="IETF Modern TLS (RFC 9325)",
            rationale=rationale,
            sources=[RFC_9325],
        )
