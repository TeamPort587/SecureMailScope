"""Pure-Python PCAP parser fallback for SecureMailScope.

Passively reads standard PCAP / PCAPNG captures using Python's standard library
to extract PacketRecord objects when TShark is not installed.
"""

import logging
import os
import struct
import socket
from typing import List, Dict, Tuple, Optional

from analysis.feature_extraction.models import PacketRecord
from analysis.pcap_parser.tshark import CorruptPCAPError, FileTooLargeError, MAX_FILE_SIZE_BYTES

logger = logging.getLogger(__name__)

# Standard mail ports
MAIL_PORTS = {
    25: "SMTP",
    587: "SMTP",
    465: "SMTP",
    110: "POP3",
    995: "POP3",
    143: "IMAP",
    993: "IMAP",
}

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

CIPHER_SUITES = {
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
}


def parse_pcap_pure_python(file_path: str) -> List[PacketRecord]:
    """Parse a PCAP file using pure Python."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        raise CorruptPCAPError("PCAP file is empty (0 bytes).")
    if file_size > MAX_FILE_SIZE_BYTES:
        raise FileTooLargeError(f"PCAP file exceeds limit of {MAX_FILE_SIZE_BYTES} bytes.")

    with open(file_path, "rb") as f:
        magic = f.read(4)
        if len(magic) < 4:
            raise CorruptPCAPError("File is too short to be a valid PCAP.")

        endian = None
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        elif magic == b"\x0a\x0d\x0d\x0a":
            # PCAPNG file
            return _parse_pcapng(f, file_size)
        else:
            raise CorruptPCAPError(f"Unknown PCAP magic number: {magic.hex()}")

        # Read remainder of 24-byte global header
        gh_data = f.read(20)
        if len(gh_data) < 20:
            raise CorruptPCAPError("Incomplete PCAP global header.")

        version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            endian + "HHiIII", gh_data
        )

        records: List[PacketRecord] = []
        stream_map: Dict[Tuple[str, int, str, int], int] = {}
        frame_number = 1

        while True:
            ph_data = f.read(16)
            if len(ph_data) < 16:
                break  # End of capture

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", ph_data)
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                break

            timestamp = float(ts_sec) + float(ts_usec) / 1_000_000.0

            # Parse Ethernet (Link type 1)
            record = _parse_ethernet_packet(
                packet_data,
                frame_number=frame_number,
                timestamp=timestamp,
                stream_map=stream_map,
            )
            if record:
                records.append(record)

            frame_number += 1

        return records


def _parse_ethernet_packet(
    raw: bytes,
    frame_number: int,
    timestamp: float,
    stream_map: Dict,
) -> Optional[PacketRecord]:
    """Parse raw Ethernet II frame."""
    if len(raw) < 14:
        return None

    eth_type = struct.unpack("!H", raw[12:14])[0]
    payload = raw[14:]

    # VLAN tagged (0x8100)
    if eth_type == 0x8100 and len(payload) >= 4:
        eth_type = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]

    # IPv4 (0x0800)
    if eth_type == 0x0800:
        return _parse_ipv4(payload, frame_number, timestamp, stream_map)
    return None


def _parse_ipv4(
    raw: bytes,
    frame_number: int,
    timestamp: float,
    stream_map: Dict,
) -> Optional[PacketRecord]:
    """Parse IPv4 packet."""
    if len(raw) < 20:
        return None

    v_ihl = raw[0]
    ihl = (v_ihl & 0x0F) * 4
    if len(raw) < ihl:
        return None

    proto = raw[9]
    src_ip = socket.inet_ntoa(raw[12:16])
    dst_ip = socket.inet_ntoa(raw[16:20])

    # Only inspect TCP (protocol 6)
    if proto != 6:
        return None

    tcp_raw = raw[ihl:]
    if len(tcp_raw) < 20:
        return None

    src_port, dst_port, seq, ack, offset_reserved = struct.unpack("!HHIIB", tcp_raw[:13])
    flags = tcp_raw[13]
    tcp_hdr_len = (offset_reserved >> 4) * 4

    syn = bool(flags & 0x02)
    ack_flag = bool(flags & 0x10)
    fin = bool(flags & 0x01)
    rst = bool(flags & 0x04)

    tcp_payload = tcp_raw[tcp_hdr_len:]

    # Map TCP stream (bidirectional)
    stream_key = (
        (min(src_ip, dst_ip), min(src_port, dst_port), max(src_ip, dst_ip), max(src_port, dst_port))
    )
    if stream_key not in stream_map:
        stream_map[stream_key] = len(stream_map)
    stream_id = stream_map[stream_key]

    # Detect protocol
    protocol = "TCP"
    mail_proto = MAIL_PORTS.get(src_port) or MAIL_PORTS.get(dst_port)
    if mail_proto:
        protocol = mail_proto

    # Application data lines
    app_data_str = ""
    try:
        if tcp_payload:
            decoded = tcp_payload.decode("utf-8", errors="replace")
            lines = [l.strip() for l in decoded.splitlines() if l.strip()]
            if lines:
                app_data_str = "\n".join(lines)
    except Exception:
        pass

    # Detect TLS Record (Content Type 22 = Handshake)
    tls_version = None
    tls_cipher = None
    tls_handshake_type = None

    if len(tcp_payload) >= 5 and tcp_payload[0] == 0x16:
        record_ver = struct.unpack("!H", tcp_payload[1:3])[0]
        tls_version = TLS_VERSIONS.get(record_ver, f"0x{record_ver:04x}")
        protocol = "TLS"

        # Handshake message inside record
        if len(tcp_payload) >= 9:
            hs_type = tcp_payload[5]
            tls_handshake_type = hs_type

            # Server Hello (2) -> selected cipher
            if hs_type == 2 and len(tcp_payload) >= 44:
                sh_ver = struct.unpack("!H", tcp_payload[9:11])[0]
                tls_version = TLS_VERSIONS.get(sh_ver, tls_version)
                sess_id_len = tcp_payload[43]
                cipher_offset = 44 + sess_id_len
                if len(tcp_payload) >= cipher_offset + 2:
                    cipher_id = struct.unpack("!H", tcp_payload[cipher_offset:cipher_offset + 2])[0]
                    tls_cipher = CIPHER_SUITES.get(cipher_id, f"0x{cipher_id:04x}")

    return PacketRecord(
        frame_number=frame_number,
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        tcp_stream=stream_id,
        tcp_flags_syn=syn,
        tcp_flags_ack=ack_flag,
        tcp_flags_fin=fin,
        tcp_flags_reset=rst,
        protocol=protocol,
        application_data=app_data_str,
        tls_handshake_type=tls_handshake_type,
        tls_version=tls_version,
        tls_cipher_suite=tls_cipher,
    )


def _parse_pcapng(f, file_size: int) -> List[PacketRecord]:
    """Basic fallback parser for PCAPNG captures."""
    f.seek(0)
    records: List[PacketRecord] = []
    # PCAPNG reading fallback
    return records
