"""TCP Session Reconstruction Engine for SecureMailScope.

Groups packets by tcp.stream, classifies completeness, and separates client/server roles.
"""

from collections import defaultdict
from typing import Dict, List, Tuple
from analysis.feature_extraction.models import PacketRecord, Session

WELL_KNOWN_EMAIL_PORTS = {
    25: "SMTP",
    465: "SMTP",
    587: "SMTP",
    143: "IMAP",
    993: "IMAP",
    110: "POP3",
    995: "POP3",
}


def _determine_protocol_from_packets(
    packets: List[PacketRecord],
    client_port: int,
    server_port: int,
) -> str:
    """Determine application protocol from packet contents and ports."""
    # Check packet protocol flags or application data
    has_smtp = False
    has_imap = False
    has_pop3 = False

    for pkt in packets:
        proto = pkt.protocol.upper()
        if proto == "SMTP":
            has_smtp = True
        elif proto == "IMAP":
            has_imap = True
        elif proto in ("POP", "POP3"):
            has_pop3 = True

        app_data = pkt.application_data.upper()
        if any(cmd in app_data for cmd in ("EHLO", "HELO", "MAIL FROM", "250-STARTTLS", "220 READY")):
            has_smtp = True
        if any(cmd in app_data for cmd in ("CAPABILITY", "AUTHENTICATE", "* OK", ". OK")):
            has_imap = True
        if any(cmd in app_data for cmd in ("+OK", "STLS", "CAPA", "USER", "PASS")):
            has_pop3 = True

    if has_smtp:
        return "SMTP"
    if has_imap:
        return "IMAP"
    if has_pop3:
        return "POP3"

    # Fallback to server port
    if server_port in WELL_KNOWN_EMAIL_PORTS:
        return WELL_KNOWN_EMAIL_PORTS[server_port]
    if client_port in WELL_KNOWN_EMAIL_PORTS:
        return WELL_KNOWN_EMAIL_PORTS[client_port]

    return "UNKNOWN"


def _determine_service(protocol: str, port: int) -> str:
    """Map protocol and port to canonical service name."""
    if protocol == "SMTP":
        if port == 587 or port == 465:
            return "submission"
        return "relay"
    elif protocol in ("IMAP", "POP3"):
        return "mail-access"
    return "unknown"


def _classify_completeness(packets: List[PacketRecord], client_packets: List[PacketRecord], server_packets: List[PacketRecord]) -> str:
    """Classify TCP session completeness as COMPLETE, PARTIAL, or UNKNOWN."""
    if len(packets) < 2:
        return "UNKNOWN"

    has_syn = any(p.tcp_flags_syn and not p.tcp_flags_ack for p in client_packets)
    has_syn_ack = any(p.tcp_flags_syn and p.tcp_flags_ack for p in server_packets)
    has_closure = any(p.tcp_flags_fin or p.tcp_flags_reset for p in packets)
    is_bidirectional = len(client_packets) > 0 and len(server_packets) > 0

    if has_syn and has_syn_ack and has_closure and is_bidirectional:
        return "COMPLETE"
    elif is_bidirectional:
        # If both sent traffic but missing clean FIN/SYN, it's partial
        return "PARTIAL"
    else:
        return "PARTIAL"


def build_sessions(packet_records: List[PacketRecord]) -> List[Session]:
    """Reconstruct TCP sessions from raw packet records.

    Args:
        packet_records: List of parsed PacketRecord objects.

    Returns:
        List of reconstructed Session objects.
    """
    streams: Dict[int, List[PacketRecord]] = defaultdict(list)
    for pkt in packet_records:
        streams[pkt.tcp_stream].append(pkt)

    sessions: List[Session] = []
    protocol_counts: Dict[str, int] = defaultdict(int)

    for stream_id, pkts in sorted(streams.items()):
        if not pkts:
            continue

        # Sort packets by frame number
        pkts.sort(key=lambda p: p.frame_number)

        # Detect client and server endpoints
        first_pkt = pkts[0]
        client_ip = first_pkt.src_ip
        client_port = first_pkt.src_port
        server_ip = first_pkt.dst_ip
        server_port = first_pkt.dst_port

        # Refine client/server endpoints using SYN or well-known server ports
        for p in pkts:
            if p.tcp_flags_syn and not p.tcp_flags_ack:
                client_ip = p.src_ip
                client_port = p.src_port
                server_ip = p.dst_ip
                server_port = p.dst_port
                break
            if p.dst_port in WELL_KNOWN_EMAIL_PORTS and p.src_port not in WELL_KNOWN_EMAIL_PORTS:
                client_ip = p.src_ip
                client_port = p.src_port
                server_ip = p.dst_ip
                server_port = p.dst_port
                break
            elif p.src_port in WELL_KNOWN_EMAIL_PORTS and p.dst_port not in WELL_KNOWN_EMAIL_PORTS:
                client_ip = p.dst_ip
                client_port = p.dst_port
                server_ip = p.src_ip
                server_port = p.src_port
                break

        # Partition packets into client and server streams
        client_pkts = [p for p in pkts if p.src_ip == client_ip and p.src_port == client_port]
        server_pkts = [p for p in pkts if p.src_ip == server_ip and p.src_port == server_port]

        # Detect protocol
        protocol = _determine_protocol_from_packets(pkts, client_port, server_port)
        service = _determine_service(protocol, server_port)

        protocol_counts[protocol] += 1
        proto_prefix = protocol.lower() if protocol in ("SMTP", "IMAP", "POP3") else "session"
        session_id = f"{proto_prefix}-{protocol_counts[protocol]:03d}"

        completeness = _classify_completeness(pkts, client_pkts, server_pkts)

        session = Session(
            session_id=session_id,
            tcp_stream=stream_id,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            protocol=protocol,
            service=service,
            completeness=completeness,
            first_frame=pkts[0].frame_number,
            last_frame=pkts[-1].frame_number,
            packet_count=len(pkts),
            packets=pkts,
            client_packets=client_pkts,
            server_packets=server_pkts,
        )
        sessions.append(session)

    return sessions
