"""SecurityProfile assembler for SecureMailScope."""

from datetime import datetime, timezone
from typing import Optional

from analysis.feature_extraction.certificate import extract_certificate_info
from analysis.feature_extraction.email_protocol import analyze_email_security
from analysis.feature_extraction.models import SecurityProfile, Session
from analysis.feature_extraction.tls import extract_tls_info


def extract_security_profile(
    session: Session,
    capture_reference_time: Optional[datetime] = None,
) -> SecurityProfile:
    """Extract and normalize a SecurityProfile from a reconstructed email session."""
    # 1. Analyze application-layer security & encryption mode
    sec_info, evidence_frames = analyze_email_security(
        packets=session.packets,
        client_packets=session.client_packets,
        server_packets=session.server_packets,
        protocol=session.protocol,
        server_port=session.server_port,
        completeness=session.completeness,
    )

    # 2. Extract TLS metadata
    tls_info = None
    if sec_info.encryption_mode in ("STARTTLS", "IMPLICIT_TLS") or sec_info.upgrade_succeeded == "YES":
        tls_info = extract_tls_info(session.packets)
        if tls_info and sec_info.upgrade_succeeded == "NO" and not tls_info.cipher_suite:
            tls_info = None

    # 3. Extract Certificate metadata
    cert_info = None
    if tls_info is not None:
        cert_info = extract_certificate_info(session.packets, tls_info)

    # Reference time determination
    ref_time = capture_reference_time
    if ref_time is None and session.packets:
        first_ts = session.packets[0].timestamp
        if first_ts > 0:
            ref_time = datetime.fromtimestamp(first_ts, tz=timezone.utc)
    if ref_time is None:
        ref_time = datetime.now(timezone.utc)

    frame_numbers = [p.frame_number for p in session.packets]

    return SecurityProfile(
        session_id=session.session_id,
        protocol=session.protocol,
        service=session.service,
        client_ip=session.client_ip,
        server_ip=session.server_ip,
        client_port=session.client_port,
        server_port=session.server_port,
        security=sec_info,
        tls=tls_info,
        certificate=cert_info,
        tcp_stream=session.tcp_stream,
        frame_numbers=frame_numbers,
        capture_reference_time=ref_time,
    )