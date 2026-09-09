"""
SecureMailScope Recommendation Catalog

Maps deterministic security finding types to actionable
security recommendations.

This file should contain recommendation definitions only.
Business logic belongs in engine.py.
"""


RECOMMENDATIONS = {
    "AUTH_BEFORE_TLS": {
        "recommendation_id": "REC-AUTH-TLS-001",
        "priority": "CRITICAL",
        "title": "Require TLS before authentication",
        "description": (
            "Configure the mail service so authentication is only "
            "permitted after a successful TLS handshake. This prevents "
            "credentials from being transmitted before encryption is "
            "established."
        ),
    },

    "PLAINTEXT": {
        "recommendation_id": "REC-PLAINTEXT-001",
        "priority": "CRITICAL",
        "title": "Disable plaintext mail sessions",
        "description": (
            "Require encrypted connections for mail protocols before "
            "transmitting authentication credentials or email data. "
            "Disable insecure plaintext access where possible."
        ),
    },

    "FAILED_STARTTLS": {
        "recommendation_id": "REC-STARTTLS-001",
        "priority": "HIGH",
        "title": "Enforce STARTTLS before authentication",
        "description": (
            "Ensure clients successfully upgrade the connection to TLS "
            "before authentication is permitted. Investigate sessions "
            "where STARTTLS was advertised but not completed."
        ),
    },

    "WEAK_TLS": {
        "recommendation_id": "REC-WEAK-TLS-001",
        "priority": "HIGH",
        "title": "Strengthen TLS configuration",
        "description": (
            "Disable outdated TLS versions and weak cryptographic "
            "configurations. Prefer modern TLS versions and strong "
            "cipher suites."
        ),
    },

    "NO_PFS": {
        "recommendation_id": "REC-PFS-001",
        "priority": "MEDIUM",
        "title": "Enable forward secrecy",
        "description": (
            "Configure TLS to use cipher suites that provide perfect "
            "forward secrecy, reducing the impact of a compromised "
            "private key on previously captured traffic."
        ),
    },

    "SELF_SIGNED_CERTIFICATE": {
        "recommendation_id": "REC-CERT-001",
        "priority": "MEDIUM",
        "title": "Use a trusted TLS certificate",
        "description": (
            "Replace self-signed certificates with certificates issued "
            "by a trusted certificate authority where appropriate, and "
            "ensure clients can validate the certificate chain."
        ),
    },

    "SMALL_CERTIFICATE_KEY": {
        "recommendation_id": "REC-CERT-KEY-001",
        "priority": "MEDIUM",
        "title": "Use adequately sized certificate keys",
        "description": (
            "Replace certificates using weak or undersized keys with "
            "certificates using currently recommended cryptographic "
            "key sizes."
        ),
    },

    "SELF_SIGNED": {
        "recommendation_id": "REC-CERT-001",
        "priority": "MEDIUM",
        "title": "Use a trusted TLS certificate",
        "description": (
            "Replace self-signed certificates with certificates issued "
            "by a trusted certificate authority where appropriate, and "
            "ensure clients can validate the certificate chain."
        ),
    },

    "DEPRECATED_TLS": {
        "recommendation_id": "REC-DEPRECATED-TLS-001",
        "priority": "HIGH",
        "title": "Upgrade deprecated TLS versions",
        "description": (
            "Disable TLS 1.0, TLS 1.1, and SSLv3 across all mail servers. "
            "Enforce TLS 1.2 or TLS 1.3."
        ),
    },

    "WEAK_CIPHER": {
        "recommendation_id": "REC-WEAK-CIPHER-001",
        "priority": "CRITICAL",
        "title": "Disable legacy and weak cipher suites",
        "description": (
            "Remove RC4, DES, 3DES, and export-grade ciphers from the server "
            "cipher suite configuration."
        ),
    },

    "EXPIRED_CERTIFICATE": {
        "recommendation_id": "REC-CERT-EXPIRED-001",
        "priority": "HIGH",
        "title": "Renew expired certificates",
        "description": (
            "Renew expired X.509 certificates and configure automated certificate "
            "renewal."
        ),
    },

    "NOT_YET_VALID_CERTIFICATE": {
        "recommendation_id": "REC-CERT-NYV-001",
        "priority": "HIGH",
        "title": "Correct certificate validity window",
        "description": (
            "Inspect system clock synchronization and certificate start times to "
            "ensure certificates are valid at current time."
        ),
    },

    "WEAK_KEY": {
        "recommendation_id": "REC-CERT-KEY-001",
        "priority": "MEDIUM",
        "title": "Upgrade certificate key size",
        "description": (
            "Reissue certificates using at least 2048-bit RSA keys or 256-bit ECDSA keys."
        ),
    },

    "INFO": {
        "recommendation_id": "REC-INFO-001",
        "priority": "INFO",
        "title": "Review observed security configuration",
        "description": (
            "Review the observed mail security configuration and "
            "continue monitoring for changes or newly detected risks."
        ),
    },
}


def get_recommendation(finding_type):
    """
    Return the recommendation associated with a finding type.

    Args:
        finding_type (str): Finding type from the Django analysis response.

    Returns:
        dict | None: Recommendation definition, or None if no
        recommendation is defined for the finding type.
    """
    return RECOMMENDATIONS.get(finding_type)