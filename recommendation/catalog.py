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