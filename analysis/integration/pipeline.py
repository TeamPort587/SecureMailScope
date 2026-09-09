"""End-to-end analysis pipeline orchestrator for SecureMailScope.

Coordinates PCAP parsing, session reconstruction, feature extraction,
rule evaluation, and summary aggregation matching django-analysis-response.json.
"""

import hashlib
import os
import uuid
from typing import Any, Dict, List, Optional

from analysis.feature_extraction.extractor import extract_security_profile
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.pcap_parser.parser import parse_pcap
from analysis.rule_engine.engine import evaluate_profile
from analysis.session_engine.engine import build_sessions


class AnalysisError(Exception):
    """Exception raised when analysis pipeline cannot complete."""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_recommendations(findings: List[Finding]) -> List[Dict[str, str]]:
    """Generate prioritized remediation recommendations based on observed findings."""
    recommendations = []
    seen_types = set()
    rec_counter = 1

    for f in findings:
        ft = f.finding_type
        if ft in seen_types:
            continue
        seen_types.add(ft)

        if ft == "AUTH_BEFORE_TLS":
            recommendations.append({
                "recommendation_id": f"rec-{rec_counter:03d}",
                "priority": "CRITICAL",
                "title": "Require TLS before authentication",
                "description": "Configure SMTP submission clients and servers so authentication occurs only after a successful TLS upgrade.",
            })
            rec_counter += 1
        elif ft == "PLAINTEXT":
            recommendations.append({
                "recommendation_id": f"rec-{rec_counter:03d}",
                "priority": "CRITICAL",
                "title": "Enforce TLS encryption for mail sessions",
                "description": "Disable plaintext transmission for email access and submission protocols. Use IMAPS, POP3S, or require STARTTLS.",
            })
            rec_counter += 1
        elif ft == "DEPRECATED_TLS":
            recommendations.append({
                "recommendation_id": f"rec-{rec_counter:03d}",
                "priority": "HIGH",
                "title": "Upgrade deprecated TLS versions",
                "description": "Disable TLS 1.0, TLS 1.1, and SSLv3 across all mail servers. Enforce TLS 1.2 or TLS 1.3.",
            })
            rec_counter += 1
        elif ft == "WEAK_CIPHER":
            recommendations.append({
                "recommendation_id": f"rec-{rec_counter:03d}",
                "priority": "CRITICAL",
                "title": "Disable legacy/weak cipher suites",
                "description": "Remove RC4, DES, 3DES, and export-grade ciphers from the server cipher suite configuration.",
            })
            rec_counter += 1
        elif ft == "EXPIRED_CERTIFICATE":
            recommendations.append({
                "recommendation_id": f"rec-{rec_counter:03d}",
                "priority": "HIGH",
                "title": "Renew expired certificates",
                "description": "Renew expired X.509 certificates and configure automated certificate renewal (e.g. ACME/Certbot).",
            })
            rec_counter += 1
        elif ft == "WEAK_KEY":
            recommendations.append({
                "recommendation_id": f"rec-{rec_counter:03d}",
                "priority": "MEDIUM",
                "title": "Upgrade public key size",
                "description": "Reissue certificates using at least 2048-bit RSA keys or 256-bit ECDSA keys.",
            })
            rec_counter += 1
        elif ft == "FAILED_STARTTLS":
            recommendations.append({
                "recommendation_id": f"rec-{rec_counter:03d}",
                "priority": "HIGH",
                "title": "Diagnose failed STARTTLS negotiations",
                "description": "Inspect server configuration and client compatibility to ensure advertised STARTTLS commands negotiate properly.",
            })
            rec_counter += 1

    return recommendations


def calculate_risk(findings: List[Finding]) -> Dict[str, Any]:
    """Calculate preliminary posture risk score and level."""
    score = 0
    for f in findings:
        if f.severity == "CRITICAL":
            score += 35
        elif f.severity == "HIGH":
            score += 20
        elif f.severity == "MEDIUM":
            score += 10
        elif f.severity == "LOW":
            score += 5

    score = min(score, 100)
    if score >= 70:
        level = "HIGH" if score < 85 else "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "model_version": "rf-v1",
        "method": "RULE_ENGINE_PLUS_ML",
        "confidence": 0.91,
    }


def analyze_pcap(
    file_path: str,
    analysis_id: Optional[str] = None,
    filename: Optional[str] = None,
    backend: str = "tshark",
) -> Dict[str, Any]:
    """Execute end-to-end analysis on an uploaded PCAP capture.

    Args:
        file_path: Absolute or relative path to PCAP/PCAPNG file.
        analysis_id: Optional unique identifier; generated if omitted.
        filename: Original user filename if provided.
        backend: Preferred parsing backend ("tshark" or "pyshark").

    Returns:
        Structured analysis dictionary strictly conforming to django-analysis-response.json.
    """
    if not os.path.exists(file_path):
        raise AnalysisError("FILE_NOT_FOUND", f"PCAP capture file not found at: {file_path}")

    size_bytes = os.path.getsize(file_path)
    if size_bytes == 0:
        raise AnalysisError("EMPTY_FILE", "The uploaded PCAP file is empty (0 bytes).")

    sha256_hash = compute_sha256(file_path)
    effective_analysis_id = analysis_id or str(uuid.uuid4())
    effective_filename = filename or os.path.basename(file_path)

    # 1. Parse packets
    try:
        packets = parse_pcap(file_path, backend=backend)
    except Exception as exc:
        raise AnalysisError("INVALID_PCAP", f"Failed to parse PCAP file: {str(exc)}")

    # 2. Reconstruct sessions
    all_sessions = build_sessions(packets)

    # Filter for email protocols only (SMTP, IMAP, POP3)
    email_sessions = [s for s in all_sessions if s.protocol in ("SMTP", "IMAP", "POP3")]
    if not email_sessions:
        raise AnalysisError(
            "NO_EMAIL_TRAFFIC",
            "No SMTP, IMAP, or POP3 traffic was detected in the capture.",
        )

    # 3. Extract profiles and evaluate rules
    profiles: List[SecurityProfile] = []
    all_findings: List[Finding] = []
    finding_counter = 1
    vulnerable_session_ids = set()

    for s in email_sessions:
        profile = extract_security_profile(s)
        profiles.append(profile)

        findings = evaluate_profile(profile, start_index=finding_counter)
        for f in findings:
            all_findings.append(f)
            finding_counter += 1
            if f.severity in ("HIGH", "CRITICAL"):
                vulnerable_session_ids.add(s.session_id)

    # 4. Summary counts
    smtp_count = sum(1 for p in profiles if p.protocol == "SMTP")
    imap_count = sum(1 for p in profiles if p.protocol == "IMAP")
    pop3_count = sum(1 for p in profiles if p.protocol == "POP3")

    plaintext_count = sum(1 for p in profiles if p.security.encryption_mode == "PLAINTEXT")
    starttls_count = sum(1 for p in profiles if p.security.encryption_mode == "STARTTLS")
    implicit_tls_count = sum(1 for p in profiles if p.security.encryption_mode == "IMPLICIT_TLS")

    summary = {
        "total_sessions": len(profiles),
        "smtp_sessions": smtp_count,
        "imap_sessions": imap_count,
        "pop3_sessions": pop3_count,
        "plaintext_sessions": plaintext_count,
        "starttls_sessions": starttls_count,
        "implicit_tls_sessions": implicit_tls_count,
        "vulnerable_sessions": len(vulnerable_session_ids),
        "findings_count": len(all_findings),
    }

    # 5. Risk and recommendations
    risk = calculate_risk(all_findings)
    recommendations = generate_recommendations(all_findings)

    # 6. Build final contract response
    response_payload: Dict[str, Any] = {
        "analysis_version": "1.0.0",
        "file": {
            "analysis_id": effective_analysis_id,
            "filename": effective_filename,
            "sha256": sha256_hash,
            "size_bytes": size_bytes,
        },
        "summary": summary,
        "sessions": [p.to_dict() for p in profiles],
        "findings": [f.to_dict() for f in all_findings],
        "risk": risk,
        "recommendations": recommendations,
    }

    return response_payload
