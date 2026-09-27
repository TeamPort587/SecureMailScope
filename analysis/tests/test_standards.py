"""Tests for Standards Context and Configuration Comparison Module."""

from datetime import datetime, timezone, timedelta
import pytest

from analysis.feature_extraction.models import (
    CertificateInfo,
    SecurityInfo,
    SecurityProfile,
    TLSInfo,
)
from analysis.standards import (
    evaluate_session_standards,
    StandardsStatus,
    VisualizationType,
)
from analysis.standards.profiles.ietf_tls import IETFModernTLSProfile
from analysis.standards.profiles.email_security import EmailSecurityProfile
from analysis.standards.profiles.nist_guidance import NISTGuidanceProfile


def _make_session(
    protocol="SMTP",
    encryption_mode="STARTTLS",
    tls_version="TLS 1.2",
    cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    pfs="YES",
    key_type="RSA",
    key_size=2048,
    cert_visibility="OBSERVED",
    valid_from=None,
    valid_until=None,
    server_port=587,
    start_time=None,
) -> SecurityProfile:
    now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    if valid_from is None:
        valid_from = (now - timedelta(days=30)).isoformat()
    if valid_until is None:
        valid_until = (now + timedelta(days=330)).isoformat()

    return SecurityProfile(
        session_id="test-session-001",
        tcp_stream=0,
        protocol=protocol,
        service="submission",
        client_ip="192.168.1.10",
        server_ip="10.0.0.1",
        client_port=50000,
        server_port=server_port,
        security=SecurityInfo(
            encryption_mode=encryption_mode,
            upgrade_advertised="YES",
            upgrade_requested="YES",
            upgrade_succeeded="YES" if encryption_mode != "PLAINTEXT" else "NO",
            authentication_before_tls="NO",
            capture_completeness="COMPLETE",
        ),
        tls=TLSInfo(version=tls_version, cipher_suite=cipher_suite, pfs=pfs) if tls_version else None,
        certificate=CertificateInfo(
            visibility=cert_visibility,
            subject="CN=mail.example.com",
            issuer="CN=Example CA",
            valid_from=valid_from,
            valid_until=valid_until,
            key_type=key_type,
            key_size=key_size,
            self_signed=False,
        ) if cert_visibility == "OBSERVED" else CertificateInfo(visibility=cert_visibility),
        start_time=start_time or now.isoformat(),
    )


class TestIETFModernTLSProfile:
    profile = IETFModernTLSProfile()

    def test_tls_1_3_is_preferred(self):
        session = _make_session(tls_version="TLS 1.3", cipher_suite="TLS_AES_256_GCM_SHA384", pfs="YES")
        results = self.profile.evaluate(session)
        res_ver = next(r for r in results if r.field == "tls_version")

        assert res_ver.status == StandardsStatus.PREFERRED
        assert res_ver.observed == "TLS 1.3"
        assert "TLS 1.3" in res_ver.preferred
        assert res_ver.visualization == VisualizationType.ORDERED_SPECTRUM
        assert any("RFC 9325" in s.name for s in res_ver.sources)

    def test_tls_1_2_is_acceptable_and_not_insecure(self):
        """CRITICAL: TLS 1.2 is ACCEPTABLE under RFC 9325 and must NOT be marked deprecated or insecure."""
        session = _make_session(tls_version="TLS 1.2", cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        results = self.profile.evaluate(session)
        res_ver = next(r for r in results if r.field == "tls_version")

        assert res_ver.status == StandardsStatus.ACCEPTABLE
        assert res_ver.observed == "TLS 1.2"
        assert "TLS 1.3" in res_ver.preferred
        assert "acceptable" in res_ver.rationale.lower()

    def test_tls_1_0_and_1_1_are_deprecated(self):
        for v in ["TLS 1.0", "TLS 1.1", "SSL 3.0"]:
            session = _make_session(tls_version=v, cipher_suite="TLS_RSA_WITH_RC4_128_SHA")
            results = self.profile.evaluate(session)
            res_ver = next(r for r in results if r.field == "tls_version")
            assert res_ver.status == StandardsStatus.DEPRECATED
            assert any("RFC 8996" in s.name for s in res_ver.sources)

    def test_aead_cipher_suite_is_preferred(self):
        session = _make_session(cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        results = self.profile.evaluate(session)
        res_cipher = next(r for r in results if r.field == "cipher_suite")

        assert res_cipher.status == StandardsStatus.PREFERRED
        assert res_cipher.visualization == VisualizationType.CATEGORICAL_SPECTRUM
        assert any("RFC 9325" in s.name for s in res_cipher.sources)

    def test_cbc_mode_cipher_is_not_recommended(self):
        session = _make_session(cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA")
        results = self.profile.evaluate(session)
        res_cipher = next(r for r in results if r.field == "cipher_suite")

        assert res_cipher.status == StandardsStatus.NOT_RECOMMENDED
        assert "CBC" in res_cipher.rationale

    def test_legacy_rc4_cipher_is_deprecated(self):
        session = _make_session(cipher_suite="TLS_RSA_WITH_RC4_128_SHA")
        results = self.profile.evaluate(session)
        res_cipher = next(r for r in results if r.field == "cipher_suite")

        assert res_cipher.status == StandardsStatus.DEPRECATED

    def test_forward_secrecy_pfs_comparison(self):
        session_pfs = _make_session(pfs="YES")
        results_pfs = self.profile.evaluate(session_pfs)
        res_pfs = next(r for r in results_pfs if r.field == "pfs")
        assert res_pfs.status == StandardsStatus.PREFERRED
        assert res_pfs.visualization == VisualizationType.CAPABILITY_COMPARISON

        session_no_pfs = _make_session(pfs="NO")
        results_no_pfs = self.profile.evaluate(session_no_pfs)
        res_no_pfs = next(r for r in results_no_pfs if r.field == "pfs")
        assert res_no_pfs.status == StandardsStatus.NOT_RECOMMENDED


class TestEmailSecurityProfile:
    profile = EmailSecurityProfile()

    def test_implicit_tls_is_preferred_under_rfc_8314(self):
        session = _make_session(encryption_mode="IMPLICIT_TLS", server_port=465)
        results = self.profile.evaluate(session)
        res_enc = next(r for r in results if r.field == "email_encryption_mode")

        assert res_enc.status == StandardsStatus.PREFERRED
        assert any("RFC 8314" in s.name for s in res_enc.sources)

    def test_starttls_is_acceptable_under_rfc_8314(self):
        session = _make_session(encryption_mode="STARTTLS", server_port=587)
        results = self.profile.evaluate(session)
        res_enc = next(r for r in results if r.field == "email_encryption_mode")

        assert res_enc.status == StandardsStatus.ACCEPTABLE
        assert "STARTTLS" in res_enc.observed

    def test_plaintext_is_deprecated_under_rfc_8314(self):
        session = _make_session(encryption_mode="PLAINTEXT", tls_version=None, server_port=25)
        results = self.profile.evaluate(session)
        res_enc = next(r for r in results if r.field == "email_encryption_mode")

        assert res_enc.status == StandardsStatus.DEPRECATED
        assert "obsolete" in res_enc.rationale.lower()


class TestNISTGuidanceProfile:
    profile = NISTGuidanceProfile()

    def test_rsa_2048_is_acceptable(self):
        session = _make_session(key_type="RSA", key_size=2048)
        results = self.profile.evaluate(session)
        res_key = next(r for r in results if r.field == "certificate_key_strength")

        assert res_key.status == StandardsStatus.ACCEPTABLE
        assert any("SP 800-52" in s.name for s in res_key.sources)

    def test_rsa_1024_is_deprecated(self):
        session = _make_session(key_type="RSA", key_size=1024)
        results = self.profile.evaluate(session)
        res_key = next(r for r in results if r.field == "certificate_key_strength")

        assert res_key.status == StandardsStatus.DEPRECATED

    def test_ec_256_is_preferred(self):
        session = _make_session(key_type="EC", key_size=256)
        results = self.profile.evaluate(session)
        res_key = next(r for r in results if r.field == "certificate_key_strength")

        assert res_key.status == StandardsStatus.PREFERRED

    def test_tls_1_3_unobservable_cert_is_not_observable_and_not_insecure(self):
        """CRITICAL: In TLS 1.3 where cert is encrypted, status must be NOT_OBSERVABLE, never 'bad cert'."""
        session = _make_session(cert_visibility="NOT_OBSERVABLE", tls_version="TLS 1.3")
        results = self.profile.evaluate(session)
        res_key = next(r for r in results if r.field == "certificate_key_strength")

        assert res_key.status == StandardsStatus.NOT_OBSERVABLE
        assert "NOT_OBSERVABLE" in str(res_key.status)
        assert res_key.visualization == VisualizationType.STATUS_ASSESSMENT

    def test_valid_certificate_during_capture(self):
        capture_time = datetime(2026, 3, 1, tzinfo=timezone.utc)
        session = _make_session(
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            start_time=capture_time.isoformat(),
        )
        results = self.profile.evaluate(session)
        res_val = next(r for r in results if r.field == "certificate_validity")

        assert res_val.status == StandardsStatus.RECOMMENDED
        assert "Valid During Session Capture" in res_val.observed


class TestStandardsEngineIntegration:
    def test_evaluate_session_standards_returns_rich_context(self):
        session = _make_session(
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            pfs="YES",
            encryption_mode="STARTTLS",
            key_type="RSA",
            key_size=2048,
        )

        standards = evaluate_session_standards(session)
        assert isinstance(standards, list)
        assert len(standards) >= 4

        fields = {item["field"] for item in standards}
        assert "tls_version" in fields
        assert "cipher_suite" in fields
        assert "pfs" in fields
        assert "email_encryption_mode" in fields

        for item in standards:
            assert "field" in item
            assert "label" in item
            assert "observed" in item
            assert "status" in item
            assert "preferred" in item
            assert "visualization" in item
            assert "profile" in item
            assert "rationale" in item
            assert "sources" in item
            assert len(item["sources"]) > 0
