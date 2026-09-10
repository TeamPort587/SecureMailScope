"""Security rules package for SecureMailScope."""

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

ALL_RULES = [
    AuthBeforeTLSRule(),
    PlaintextRule(),
    FailedSTARTTLSRule(),
    DeprecatedTLSRule(),
    WeakCipherRule(),
    ExpiredCertificateRule(),
    NotYetValidCertificateRule(),
    WeakKeyRule(),
    PFSRule(),
    SelfSignedCertificateRule(),
]

__all__ = [
    "ALL_RULES",
    "AuthBeforeTLSRule",
    "PlaintextRule",
    "FailedSTARTTLSRule",
    "DeprecatedTLSRule",
    "WeakCipherRule",
    "ExpiredCertificateRule",
    "NotYetValidCertificateRule",
    "WeakKeyRule",
    "PFSRule",
    "SelfSignedCertificateRule",
]
