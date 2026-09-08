"""PyShark adapter backend for SecureMailScope.

Provides secondary/fallback parsing using PyShark FileCapture.
"""

import logging
import os
from typing import List, Optional

from analysis.feature_extraction.models import PacketRecord
from analysis.pcap_parser.tshark import CorruptPCAPError, FileTooLargeError, MAX_FILE_SIZE_BYTES

logger = logging.getLogger(__name__)


def parse_pcap_with_pyshark(file_path: str) -> List[PacketRecord]:
    """Parse a PCAP file using PyShark."""
    import pyshark

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        raise CorruptPCAPError("PCAP file is empty (0 bytes).")
    if file_size > MAX_FILE_SIZE_BYTES:
        raise FileTooLargeError(
            f"PCAP file size ({file_size} bytes) exceeds limit of {MAX_FILE_SIZE_BYTES} bytes."
        )

    records: List[PacketRecord] = []
    try:
        cap = pyshark.FileCapture(
            file_path,
            keep_packets=False,
            display_filter="tcp",
        )
        for pkt in cap:
            try:
                frame_number = int(pkt.frame_info.number)
                timestamp = float(pkt.sniff_timestamp)
                src_ip = getattr(pkt.ip, "src", getattr(pkt.ipv6, "src", "0.0.0.0")) if hasattr(pkt, "ip") or hasattr(pkt, "ipv6") else "0.0.0.0"
                dst_ip = getattr(pkt.ip, "dst", getattr(pkt.ipv6, "dst", "0.0.0.0")) if hasattr(pkt, "ip") or hasattr(pkt, "ipv6") else "0.0.0.0"
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
                tcp_stream = int(pkt.tcp.stream)

                syn_flag = bool(getattr(pkt.tcp, "flags_syn", "0") == "1")
                ack_flag = bool(getattr(pkt.tcp, "flags_ack", "0") == "1")
                fin_flag = bool(getattr(pkt.tcp, "flags_fin", "0") == "1")
                rst_flag = bool(getattr(pkt.tcp, "flags_reset", "0") == "1")

                protocol = "TCP"
                app_data = ""
                if hasattr(pkt, "smtp"):
                    protocol = "SMTP"
                elif hasattr(pkt, "imap"):
                    protocol = "IMAP"
                elif hasattr(pkt, "pop"):
                    protocol = "POP3"
                elif hasattr(pkt, "tls"):
                    protocol = "TLS"

                record = PacketRecord(
                    frame_number=frame_number,
                    timestamp=timestamp,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    tcp_stream=tcp_stream,
                    tcp_flags_syn=syn_flag,
                    tcp_flags_ack=ack_flag,
                    tcp_flags_fin=fin_flag,
                    tcp_flags_reset=rst_flag,
                    protocol=protocol,
                    application_data=app_data,
                )
                records.append(record)
            except Exception as e:
                logger.debug(f"Skipping unparseable packet: {e}")
                continue
        cap.close()
    except Exception as exc:
        raise CorruptPCAPError(f"PyShark parsing failed: {exc}")

    return records
