"""Unified PCAP parser entrypoint for SecureMailScope."""

import logging
from typing import List

from analysis.feature_extraction.models import PacketRecord
from analysis.pcap_parser.tshark import (
    CorruptPCAPError,
    FileTooLargeError,
    PCAPParserError,
    parse_pcap_with_tshark,
)

logger = logging.getLogger(__name__)


def parse_pcap(file_path: str, backend: str = "tshark") -> List[PacketRecord]:
    """Parse a PCAP or PCAPNG file and return normalized PacketRecord objects.

    Args:
        file_path: Path to capture file.
        backend: Preferred backend ("tshark" or "pyshark").

    Returns:
        List of PacketRecord objects.

    Raises:
        FileNotFoundError: If capture file does not exist.
        CorruptPCAPError: If file is empty or corrupted.
        FileTooLargeError: If file exceeds size limit.
    """
    try:
        if backend == "pyshark":
            try:
                from analysis.pcap_parser.pyshark_adapter import parse_pcap_with_pyshark
                return parse_pcap_with_pyshark(file_path)
            except Exception as exc:
                logger.warning(f"PyShark parsing failed ({exc}), falling back to TShark JSON.")
                return parse_pcap_with_tshark(file_path)

        return parse_pcap_with_tshark(file_path)
    except FileNotFoundError as fnf_err:
        logger.warning(f"TShark not found ({fnf_err}), using pure Python PCAP fallback parser.")
        from analysis.pcap_parser.python_pcap import parse_pcap_pure_python
        return parse_pcap_pure_python(file_path)
