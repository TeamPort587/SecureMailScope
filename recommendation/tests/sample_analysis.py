"""
Sample Django analysis response for testing
SecureMailScope intelligence pipeline.
"""


DJANGO_ANALYSIS = {
    "analysis_version": "1.0.0",

    "file": {
        "analysis_id": "test-analysis-001",
        "filename": "smtp_capture.pcap",
        "sha256": "test-sha256",
        "size_bytes": 1847296,
    },

    "summary": {
        "total_sessions": 4,
        "smtp_sessions": 2,
        "imap_sessions": 1,
        "pop3_sessions": 1,
        "plaintext_sessions": 1,
        "starttls_sessions": 2,
        "implicit_tls_sessions": 1,
        "vulnerable_sessions": 2,
        "findings_count": 5,
    },

    "sessions": [
        {
            "session_id": "smtp-001",
            "protocol": "SMTP",
            "service": "submission",
            "security": {
                "encryption_mode": "STARTTLS",
                "upgrade_advertised": "YES",
                "upgrade_requested": "YES",
                "upgrade_succeeded": "YES",
                "authentication_before_tls": "NO",
                "capture_completeness": "COMPLETE",
            },
        },
        {
            "session_id": "smtp-002",
            "protocol": "SMTP",
            "service": "submission",
            "security": {
                "encryption_mode": "STARTTLS",
                "upgrade_advertised": "YES",
                "upgrade_requested": "NO",
                "upgrade_succeeded": "NO",
                "authentication_before_tls": "YES",
                "capture_completeness": "COMPLETE",
            },
        },
        {
            "session_id": "imap-001",
            "protocol": "IMAP",
            "service": "mail-access",
            "security": {
                "encryption_mode": "PLAINTEXT",
                "upgrade_advertised": "NO",
                "upgrade_requested": "NO",
                "upgrade_succeeded": "NO",
                "authentication_before_tls": "YES",
                "capture_completeness": "COMPLETE",
            },
        },
        {
            "session_id": "pop3-001",
            "protocol": "POP3",
            "service": "mail-access",
            "security": {
                "encryption_mode": "IMPLICIT_TLS",
                "upgrade_advertised": "UNKNOWN",
                "upgrade_requested": "UNKNOWN",
                "upgrade_succeeded": "YES",
                "authentication_before_tls": "NO",
                "capture_completeness": "PARTIAL",
            },
        },
    ],

    "findings": [
        {
            "finding_id": "finding-001",
            "session_id": "smtp-002",
            "finding_type": "AUTH_BEFORE_TLS",
            "severity": "CRITICAL",
            "title": "Authentication occurred before TLS",
            "description": "Authentication was observed before TLS.",
            "confidence": "OBSERVED",
        },
        {
            "finding_id": "finding-002",
            "session_id": "imap-001",
            "finding_type": "PLAINTEXT",
            "severity": "CRITICAL",
            "title": "IMAP session was transmitted in plaintext",
            "description": "IMAP traffic was observed without encryption.",
            "confidence": "OBSERVED",
        },
        {
            "finding_id": "finding-003",
            "session_id": "smtp-002",
            "finding_type": "FAILED_STARTTLS",
            "severity": "HIGH",
            "title": "STARTTLS was advertised but not completed",
            "description": "STARTTLS was not completed.",
            "confidence": "OBSERVED",
        },
        {
            "finding_id": "finding-004",
            "session_id": "smtp-001",
            "finding_type": "PFS",
            "severity": "INFO",
            "title": "Forward secrecy was observed",
            "description": "Forward secrecy was observed.",
            "confidence": "OBSERVED",
        },
        {
            "finding_id": "finding-005",
            "session_id": "pop3-001",
            "finding_type": "PFS",
            "severity": "INFO",
            "title": "Forward secrecy was observed",
            "description": "Forward secrecy was inferred.",
            "confidence": "INFERRED",
        },
    ],
}


ML_RESULT = {
    "ml_risk_level": "HIGH",

    "confidence": 0.91,

    "model": {
        "name": "securemailscope_random_forest",
        "version": "rf-v1",
    },

    "session_predictions": [
        {
            "session_id": "smtp-001",
            "risk_level": "LOW",
            "confidence": 0.94,
        },
        {
            "session_id": "smtp-002",
            "risk_level": "CRITICAL",
            "confidence": 0.99,
        },
        {
            "session_id": "imap-001",
            "risk_level": "CRITICAL",
            "confidence": 0.99,
        },
        {
            "session_id": "pop3-001",
            "risk_level": "LOW",
            "confidence": 0.90,
        },
    ],
}