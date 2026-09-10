"""API endpoint integration tests using Django REST Framework test client."""

import io
import pytest
from rest_framework import status
from rest_framework.test import APIClient


@pytest.fixture
def api_client():
    return APIClient()


def test_health_check_endpoint(api_client):
    response = api_client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "healthy"


def test_internal_analyze_missing_file(api_client):
    response = api_client.post("/internal/analyze", {})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert data["status"] == "failed"
    assert data["error"]["code"] == "MISSING_FILE"


def test_internal_analyze_success(api_client, monkeypatch):
    # Mock analyze_pcap to return a contract-conforming payload
    mock_response = {
        "analysis_version": "1.0.0",
        "file": {
            "analysis_id": "test-uuid-1234",
            "filename": "smtp_sample.pcap",
            "sha256": "abcdef1234567890",
            "size_bytes": 1024,
        },
        "summary": {
            "total_sessions": 1,
            "smtp_sessions": 1,
            "imap_sessions": 0,
            "pop3_sessions": 0,
            "plaintext_sessions": 0,
            "starttls_sessions": 1,
            "implicit_tls_sessions": 0,
            "vulnerable_sessions": 0,
            "findings_count": 0,
        },
        "sessions": [
            {
                "session_id": "smtp-001",
                "protocol": "SMTP",
                "risk_label": "LOW",
            }
        ],
        "findings": [],
        "recommendations": [],
    }

    monkeypatch.setattr(
        "analysis.api.views.analyze_pcap",
        lambda file_path, analysis_id=None, filename=None: mock_response,
    )

    fake_file = io.BytesIO(b"DUMMY_PCAP_BINARY_STREAM")
    fake_file.name = "smtp_sample.pcap"

    response = api_client.post(
        "/internal/analyze",
        {"file": fake_file, "analysis_id": "test-uuid-1234"},
        format="multipart",
    )

    assert response.status_code == status.HTTP_200_OK
    res_data = response.json()
    assert res_data["analysis_version"] == "1.0.0"
    assert res_data["file"]["analysis_id"] == "test-uuid-1234"
    assert res_data["file"]["filename"] == "smtp_sample.pcap"
    assert "summary" in res_data
    assert len(res_data["sessions"]) == 1
    assert res_data["sessions"][0]["risk_label"] == "LOW"
    assert "risk" not in res_data


def test_internal_analyze_controlled_error(api_client, monkeypatch):
    from analysis.integration.pipeline import AnalysisError

    def _raise_error(*args, **kwargs):
        raise AnalysisError("NO_EMAIL_TRAFFIC", "No SMTP, IMAP, or POP3 traffic was detected.")

    monkeypatch.setattr("analysis.api.views.analyze_pcap", _raise_error)

    fake_file = io.BytesIO(b"NON_EMAIL_PCAP_DATA")
    fake_file.name = "dns_only.pcap"

    response = api_client.post(
        "/internal/analyze",
        {"file": fake_file},
        format="multipart",
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    res_data = response.json()
    assert res_data["status"] == "failed"
    assert res_data["error"]["code"] == "NO_EMAIL_TRAFFIC"
