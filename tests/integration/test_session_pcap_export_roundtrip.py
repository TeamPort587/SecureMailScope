"""Session PCAP Export & Round-Trip Forensic Verification Tests.

Covers Sections 21 & 22 specifications:
- Analyze capture
- Select individual session / TCP stream
- Export isolated session PCAP
- Programmatically verify packet count, stream membership, timestamp ordering
- Verify absence of unrelated sessions
- Verify Wireshark / TShark readability
- Round-trip forensic test:
    Original PCAP -> SecureMailScope Analysis -> Session Finding
    -> Export Session PCAP -> Re-analyze exported PCAP -> Verify Finding
"""

import os
import tempfile
import struct
import pytest

from analysis.integration.pipeline import analyze_pcap
from analysis.session_engine.exporter import extract_session_pcap, find_tshark_binary


VALIDATION_PCAP_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "captures",
    "validation",
)
VALIDATION_01 = os.path.join(VALIDATION_PCAP_DIR, "validation_01.pcap")


class TestSessionPcapExport:
    @pytest.mark.skipif(not os.path.isfile(VALIDATION_01), reason="validation_01.pcap not present")
    def test_export_stream_0_contains_only_session_packets(self):
        """Export TCP stream 0 from validation_01.pcap and verify packet contents."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            info = extract_session_pcap(
                source_pcap_path=VALIDATION_01,
                target_pcap_path=tmp_path,
                tcp_stream=0,
                backend="auto",
            )

            assert os.path.exists(tmp_path)
            assert os.path.getsize(tmp_path) > 0
            assert info["tcp_stream"] == 0
            assert info["packet_count"] > 0
            assert info["wireshark_filter"] == "tcp.stream == 0"
            assert info["source_pcap_sha256"] is not None
            assert info["extracted_pcap_sha256"] is not None

            # Verify exported file has standard PCAP global header
            with open(tmp_path, "rb") as f:
                magic = f.read(4)
                assert magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    @pytest.mark.skipif(not os.path.isfile(VALIDATION_01), reason="validation_01.pcap not present")
    def test_exported_session_pcap_is_readable_by_tshark(self):
        """Verify the exported session PCAP can be parsed by tshark without errors."""
        tshark_bin = find_tshark_binary()
        if not tshark_bin:
            pytest.skip("tshark not installed in environment")

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            extract_session_pcap(VALIDATION_01, tmp_path, tcp_stream=0)

            # Re-read with tshark
            import subprocess
            res = subprocess.run(
                [tshark_bin, "-r", tmp_path, "-T", "fields", "-e", "tcp.stream", "-e", "frame.number"],
                capture_output=True,
                text=True,
                check=True,
            )

            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            assert len(lines) > 0

            # In the isolated capture, all packets belong to stream 0 (the only stream in that capture)
            for line in lines:
                parts = line.split("\t")
                if len(parts) >= 1 and parts[0]:
                    assert parts[0] == "0"

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestRoundTripForensicVerification:
    @pytest.mark.skipif(not os.path.isfile(VALIDATION_01), reason="validation_01.pcap not present")
    def test_round_trip_analysis_export_reanalysis(self):
        """Section 22: Round-Trip Forensic Test.

        1. Ingest original PCAP with SecureMailScope pipeline.
        2. Identify a session and its findings.
        3. Export that session's isolated evidence PCAP.
        4. Re-analyze the extracted session PCAP with SecureMailScope pipeline.
        5. Verify that the session security properties and findings are preserved!
        """
        # Step 1: Ingest original PCAP
        orig_analysis = analyze_pcap(
            file_path=VALIDATION_01,
            analysis_id="orig-test-01",
            filename="validation_01.pcap",
        )

        assert len(orig_analysis["sessions"]) > 0
        target_session = orig_analysis["sessions"][0]
        stream_id = target_session.get("tcp_stream", 0)

        # Step 2: Export isolated session PCAP
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            extracted_path = tmp.name

        try:
            export_info = extract_session_pcap(
                source_pcap_path=VALIDATION_01,
                target_pcap_path=extracted_path,
                tcp_stream=stream_id,
            )
            assert export_info["packet_count"] > 0

            # Step 3: Re-analyze the extracted session PCAP independently
            roundtrip_analysis = analyze_pcap(
                file_path=extracted_path,
                analysis_id="roundtrip-test-01",
                filename="extracted_stream.pcap",
            )

            # In the extracted PCAP, exactly 1 session exists
            assert len(roundtrip_analysis["sessions"]) == 1
            rt_session = roundtrip_analysis["sessions"][0]

            # Step 4: Verify forensic fidelity
            assert rt_session["protocol"] == target_session["protocol"]
            assert rt_session["security"]["encryption_mode"] == target_session["security"]["encryption_mode"]
            assert rt_session["security"]["authentication_before_tls"] == target_session["security"]["authentication_before_tls"]

            # Findings for this session match
            orig_findings = [f["finding_type"] for f in orig_analysis["findings"] if f["session_id"] == target_session["session_id"]]
            rt_findings = [f["finding_type"] for f in roundtrip_analysis["findings"]]

            for ft in orig_findings:
                assert ft in rt_findings

        finally:
            if os.path.exists(extracted_path):
                os.remove(extracted_path)
