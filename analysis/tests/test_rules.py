"""Table-driven unit tests for all deterministic security rules."""

import pytest
from analysis.feature_extraction.models import (
    CertificateInfo,
    SecurityInfo,
    SecurityProfile,
    TLSInfo,
)
from analysis.rule_engine.engine import evaluate_profile
from analysis.rule_engine.rules.auth_before_tls import AuthBeforeTLSRule
from analysis.rule_engine.rules.deprecated_tls import DeprecatedTLSRule
from analysis.rule_engine.rules.expired_certificate import ExpiredCertificateRule
from analysis.rule_engine.rules.failed_starttls import FailedSTARTTLSRule
from analysis.rule_engine.rules.not_yet_valid_certificate import (
    NotYetValidCertificateRule,
)
from analysis.rule_engine.rules.pfs import PFSRule
from analysis.rule_engine.rules.plaintext import PlaintextRule
from analysis.rule_engine.rules.self_signed import SelfSignedCertificateRule
from analysis.rule_engine.rules.weak_cipher import WeakCipherRule
from analysis.rule_engine.rules.weak_key import WeakKeyRule


class TestDeprecatedTLSRule:
    @pytest.mark.parametrize(
        "version, expected_trigger",
        [
            ("SSLv3", True),
            ("TLS 1.0", True),
            ("TLS 1.1", True),
            ("TLS 1.2", False),
            ("TLS 1.3", False),
            (None, False),
            ("UNKNOWN", False),
        ],
    )
    def test_deprecated_tls_cases(self, clean_smtp_tls_profile, version, expected_trigger):
        rule = DeprecatedTLSRule()
        clean_smtp_tls_profile.tls.version = version
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")

        if expected_trigger:
            assert finding is not None
            assert finding.finding_type == "DEPRECATED_TLS"
            assert finding.severity == "HIGH"
            assert finding.evidence["tls_version"] == version
        else:
            assert finding is None


class TestWeakCipherRule:
    @pytest.mark.parametrize(
        "cipher, expected_trigger",
        [
            ("TLS_RSA_WITH_RC4_128_SHA", True),
            ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", True),
            ("TLS_RSA_WITH_DES_CBC_SHA", True),
            ("TLS_RSA_WITH_NULL_SHA256", True),
            ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", True),
            ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", False),
            ("TLS_AES_256_GCM_SHA384", False),
            (None, False),
        ],
    )
    def test_weak_cipher_cases(self, clean_smtp_tls_profile, cipher, expected_trigger):
        rule = WeakCipherRule()
        clean_smtp_tls_profile.tls.cipher_suite = cipher
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")

        if expected_trigger:
            assert finding is not None
            assert finding.finding_type == "WEAK_CIPHER"
            assert finding.severity == "CRITICAL"
            assert finding.evidence["cipher_suite"] == cipher
        else:
            assert finding is None


class TestCertificateValidityRules:
    def test_expired_certificate(self, expired_cert_profile):
        rule = ExpiredCertificateRule()
        finding = rule.evaluate(expired_cert_profile, "f1")
        assert finding is not None
        assert finding.finding_type == "EXPIRED_CERTIFICATE"
        assert finding.severity == "HIGH"
        assert "valid_until" in finding.evidence

    def test_valid_certificate_does_not_trigger_expired(self, clean_smtp_tls_profile):
        rule = ExpiredCertificateRule()
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")
        assert finding is None

    def test_not_yet_valid_certificate(self, not_yet_valid_cert_profile):
        rule = NotYetValidCertificateRule()
        finding = rule.evaluate(not_yet_valid_cert_profile, "f1")
        assert finding is not None
        assert finding.finding_type == "NOT_YET_VALID_CERTIFICATE"
        assert finding.severity == "HIGH"
        assert "valid_from" in finding.evidence

    def test_unobservable_cert_does_not_trigger(self, implicit_tls_profile):
        rule1 = ExpiredCertificateRule()
        rule2 = NotYetValidCertificateRule()
        assert rule1.evaluate(implicit_tls_profile, "f1") is None
        assert rule2.evaluate(implicit_tls_profile, "f2") is None


class TestWeakKeyRule:
    @pytest.mark.parametrize(
        "key_type, key_size, expected_trigger",
        [
            ("RSA", 1024, True),
            ("RSA", 512, True),
            ("RSA", 2048, False),
            ("RSA", 4096, False),
            ("EC", 224, True),
            ("ECDSA", 256, False),
            ("RSA", None, False),
        ],
    )
    def test_weak_key_cases(self, clean_smtp_tls_profile, key_type, key_size, expected_trigger):
        rule = WeakKeyRule()
        clean_smtp_tls_profile.certificate.key_type = key_type
        clean_smtp_tls_profile.certificate.key_size = key_size
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")

        if expected_trigger:
            assert finding is not None
            assert finding.finding_type == "WEAK_KEY"
            assert finding.severity == "MEDIUM"
            assert finding.evidence["key_size"] == key_size
        else:
            assert finding is None


class TestAuthBeforeTLSRule:
    def test_auth_before_tls_positive(self, auth_before_tls_profile):
        rule = AuthBeforeTLSRule()
        finding = rule.evaluate(auth_before_tls_profile, "f1")
        assert finding is not None
        assert finding.finding_type == "AUTH_BEFORE_TLS"
        assert finding.severity == "CRITICAL"
        assert finding.evidence["authentication_before_tls"] is True

    def test_auth_before_tls_negative(self, clean_smtp_tls_profile):
        rule = AuthBeforeTLSRule()
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")
        assert finding is None


class TestFailedSTARTTLSRule:
    def test_failed_starttls_positive(self, failed_starttls_profile):
        rule = FailedSTARTTLSRule()
        finding = rule.evaluate(failed_starttls_profile, "f1")
        assert finding is not None
        assert finding.finding_type == "FAILED_STARTTLS"
        assert finding.severity == "HIGH"
        assert finding.evidence["upgrade_advertised"] == "YES"
        assert finding.evidence["upgrade_succeeded"] == "NO"

    def test_failed_starttls_negative(self, clean_smtp_tls_profile):
        rule = FailedSTARTTLSRule()
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")
        assert finding is None


class TestPlaintextRule:
    def test_plaintext_positive(self, plaintext_imap_profile):
        rule = PlaintextRule()
        finding = rule.evaluate(plaintext_imap_profile, "f1")
        assert finding is not None
        assert finding.finding_type == "PLAINTEXT"
        assert finding.severity == "CRITICAL"
        assert finding.evidence["encryption_mode"] == "PLAINTEXT"

    def test_plaintext_negative(self, clean_smtp_tls_profile):
        rule = PlaintextRule()
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")
        assert finding is None


class TestPFSRule:
    def test_pfs_observed_info(self, clean_smtp_tls_profile):
        rule = PFSRule()
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")
        assert finding is not None
        assert finding.finding_type == "PFS"
        assert finding.severity == "INFO"
        assert finding.evidence["pfs"] == "YES"

    def test_pfs_missing_medium(self, clean_smtp_tls_profile):
        rule = PFSRule()
        clean_smtp_tls_profile.tls.pfs = "NO"
        clean_smtp_tls_profile.tls.cipher_suite = "TLS_RSA_WITH_AES_128_CBC_SHA"
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")
        assert finding is not None
        assert finding.finding_type == "PFS"
        assert finding.severity == "MEDIUM"
        assert finding.evidence["pfs"] == "NO"

    def test_pfs_unknown_no_finding(self, clean_smtp_tls_profile):
        rule = PFSRule()
        clean_smtp_tls_profile.tls.pfs = "UNKNOWN"
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")
        assert finding is None


class TestSelfSignedRule:
    def test_self_signed_positive(self, self_signed_profile):
        rule = SelfSignedCertificateRule()
        finding = rule.evaluate(self_signed_profile, "f1")
        assert finding is not None
        assert finding.finding_type == "SELF_SIGNED"
        assert finding.severity == "LOW"

    def test_self_signed_negative(self, clean_smtp_tls_profile):
        rule = SelfSignedCertificateRule()
        finding = rule.evaluate(clean_smtp_tls_profile, "f1")
        assert finding is None


class TestEngineEvaluation:
    def test_multiple_findings_on_vulnerable_profile(self, base_reference_time):
        # Profile with TLS 1.0, RC4, weak 1024 RSA key, expired certificate
        vuln_profile = SecurityProfile(
            session_id="smtp-multi-vuln",
            protocol="SMTP",
            service="submission",
            client_ip="10.0.1.100",
            server_ip="203.0.113.100",
            client_port=49999,
            server_port=587,
            security=SecurityInfo(
                encryption_mode="STARTTLS",
                upgrade_advertised="YES",
                upgrade_requested="YES",
                upgrade_succeeded="YES",
                authentication_before_tls="NO",
                capture_completeness="COMPLETE",
            ),
            tls=TLSInfo(
                version="TLS 1.0",
                cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
                pfs="NO",
            ),
            certificate=CertificateInfo(
                visibility="OBSERVED",
                subject="CN=multi.example.com",
                issuer="CN=multi.example.com",
                valid_from="2020-01-01T00:00:00Z",
                valid_until="2022-01-01T00:00:00Z",
                key_type="RSA",
                key_size=1024,
                self_signed=True,
            ),
            tcp_stream=99,
            frame_numbers=[1, 2, 3],
            capture_reference_time=base_reference_time,
        )

        findings = evaluate_profile(vuln_profile)
        types = [f.finding_type for f in findings]
        assert "DEPRECATED_TLS" in types
        assert "WEAK_CIPHER" in types
        assert "EXPIRED_CERTIFICATE" in types
        assert "WEAK_KEY" in types
        assert "PFS" in types
        assert "SELF_SIGNED" in types
        assert len(findings) == 6
