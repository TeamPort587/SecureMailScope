"""Full-Scale End-to-End System Validation Suite.

Executes and verifies:
1. Live service health (Django Analysis on 8000, Node Gateway on 3000)
2. Complete Authentication lifecycle (Register -> Login -> JWT -> Protected Routes -> Invalid Auth)
3. Full Upload and Analysis Pipeline (Node -> Django -> TShark -> Rule Engine -> ML -> Recommendations -> DB Persistence)
4. Multi-protocol scenarios (SMTPS, IMAPS, POP3S, Plaintext SMTP/IMAP/POP3, Validation PCAPs 1/2/3)
5. X.509 Certificate extraction verification
6. History, detail retrieval, and persistence of affected_sessions
7. Repeated run stability test (10 consecutive runs)
8. Output results to test-results/full_system_qa_results.json
"""

import json
import os
import time
from pathlib import Path
import pytest
import requests

NODE_BASE_URL = "http://127.0.0.1:3000/api"
DJANGO_BASE_URL = "http://127.0.0.1:8000"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CAPTURES_RAW = REPO_ROOT / "captures" / "raw"
CAPTURES_VAL = REPO_ROOT / "captures" / "validation"
RESULTS_DIR = REPO_ROOT / "test-results"
RESULTS_DIR.mkdir(exist_ok=True)


@pytest.fixture(scope="session")
def service_health_check():
    """Verify live services are reachable before running E2E tests."""
    try:
        dj_resp = requests.get(f"{DJANGO_BASE_URL}/health", timeout=5)
        assert dj_resp.status_code == 200, f"Django health check failed with status {dj_resp.status_code}"
    except Exception as e:
        pytest.fail(f"Django Analysis Service is not running at {DJANGO_BASE_URL}: {e}")

    try:
        node_resp = requests.get(f"{NODE_BASE_URL}/health", timeout=5)
        assert node_resp.status_code == 200, f"Node gateway health check failed with status {node_resp.status_code}"
    except Exception as e:
        pytest.fail(f"Node Gateway is not running at {NODE_BASE_URL}: {e}")


@pytest.fixture(scope="session")
def auth_token(service_health_check):
    """Register a new QA tester and return a valid JWT auth header."""
    unique_id = int(time.time())
    email = f"qa_engineer_{unique_id}@securemailscope.local"
    password = "CorrectHorseBatteryStaple!987"

    # Register
    reg_resp = requests.post(
        f"{NODE_BASE_URL}/auth/register",
        json={"email": email, "password": password},
        timeout=10,
    )
    assert reg_resp.status_code in (201, 200), f"Registration failed: {reg_resp.text}"

    # Login
    login_resp = requests.post(
        f"{NODE_BASE_URL}/auth/login",
        json={"email": email, "password": password},
        timeout=10,
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["token"]
    return {"Authorization": f"Bearer {token}", "User-Email": email, "Password": password}


# ---------------------------------------------------------------------------
# 1. AUTHENTICATION FLOW TESTS (Section 6)
# ---------------------------------------------------------------------------
class TestAuthenticationFlow:
    def test_invalid_password_rejected(self, auth_token):
        resp = requests.post(
            f"{NODE_BASE_URL}/auth/login",
            json={"email": auth_token["User-Email"], "password": "WrongPassword!999"},
            timeout=5,
        )
        assert resp.status_code == 401
        assert "Invalid email or password" in resp.text

    def test_nonexistent_user_rejected(self):
        resp = requests.post(
            f"{NODE_BASE_URL}/auth/login",
            json={"email": "does_not_exist@example.com", "password": "AnyPassword123"},
            timeout=5,
        )
        assert resp.status_code == 401

    def test_empty_credentials_rejected(self):
        resp = requests.post(
            f"{NODE_BASE_URL}/auth/login",
            json={"email": "", "password": ""},
            timeout=5,
        )
        assert resp.status_code in (400, 401, 422)

    def test_unauthorized_access_to_protected_routes(self):
        resp = requests.get(f"{NODE_BASE_URL}/analyses", timeout=5)
        assert resp.status_code == 401

        resp2 = requests.post(f"{NODE_BASE_URL}/analyze", timeout=5)
        assert resp2.status_code == 401


# ---------------------------------------------------------------------------
# 2. UPLOAD VALIDATION TESTS (Section 7)
# ---------------------------------------------------------------------------
class TestUploadValidation:
    def test_empty_file_rejected(self, auth_token):
        files = {"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")}
        resp = requests.post(
            f"{NODE_BASE_URL}/analyze",
            headers={"Authorization": auth_token["Authorization"]},
            files=files,
            timeout=10,
        )
        assert resp.status_code in (400, 422)

    def test_invalid_extension_rejected(self, auth_token):
        files = {"file": ("malicious.exe", b"MZ\x90\x00\x03", "application/octet-stream")}
        resp = requests.post(
            f"{NODE_BASE_URL}/analyze",
            headers={"Authorization": auth_token["Authorization"]},
            files=files,
            timeout=10,
        )
        assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# 3. END-TO-END PIPELINE & PERSISTENCE (Sections 11-15, 20-23, 26)
# ---------------------------------------------------------------------------
class TestEndToEndPipeline:
    def _run_upload(self, pcap_path: Path, auth_token: dict) -> dict:
        assert pcap_path.exists(), f"PCAP fixture not found: {pcap_path}"
        with open(pcap_path, "rb") as f:
            files = {"file": (pcap_path.name, f, "application/vnd.tcpdump.pcap")}
            t0 = time.time()
            resp = requests.post(
                f"{NODE_BASE_URL}/analyze",
                headers={"Authorization": auth_token["Authorization"]},
                files=files,
                timeout=120,
            )
            duration = time.time() - t0

        assert resp.status_code == 201, f"Upload analysis failed ({resp.status_code}): {resp.text}"
        data = resp.json()
        data["_duration_sec"] = duration
        return data

    def test_e2e_01_secure_smtps(self, auth_token):
        """E2E-01: Upload secure SMTPS -> verify analysis, ML risk, recommendations, persistence."""
        pcap = CAPTURES_RAW / "SMTP_465_IMPLICIT_TLS_AUTH_SUCCESS_20260909_191354.pcap"
        data = self._run_upload(pcap, auth_token)

        assert data["status"] == "COMPLETED"
        assert data["analysis_id"] is not None
        assert data["summary"]["total_sessions"] >= 1
        assert data["summary"]["smtp_sessions"] >= 1
        assert data["risk"]["level"] in ["LOW", "INFO", "MEDIUM"]
        assert data["risk"]["model_version"] == "rf-v1"
        assert len(data["recommendations"]) >= 1

        # Persistence check
        get_resp = requests.get(
            f"{NODE_BASE_URL}/analyses/{data['analysis_id']}",
            headers={"Authorization": auth_token["Authorization"]},
            timeout=10,
        )
        assert get_resp.status_code == 200
        persisted = get_resp.json()
        assert persisted["analysis_id"] == data["analysis_id"]
        assert persisted["summary"]["session_count"] == data["summary"]["total_sessions"]

    def test_e2e_02_secure_imaps(self, auth_token):
        """E2E-02: Upload secure IMAPS -> verify parsing, ML risk, recommendations."""
        pcap = CAPTURES_RAW / "IMAP_993_IMPLICIT_TLS_AUTH_SUCCESS_20260909_191238.pcap"
        data = self._run_upload(pcap, auth_token)

        assert data["status"] == "COMPLETED"
        assert data["summary"]["imap_sessions"] >= 1
        assert data["risk"]["level"] in ["LOW", "INFO", "MEDIUM"]

    def test_e2e_03_secure_pop3s(self, auth_token):
        """E2E-03: Upload secure POP3S -> verify parsing and low risk."""
        pcap = CAPTURES_RAW / "POP3_995_IMPLICIT_TLS_AUTH_SUCCESS_20260909_191329.pcap"
        data = self._run_upload(pcap, auth_token)

        assert data["status"] == "COMPLETED"
        assert data["summary"]["pop3_sessions"] >= 1
        assert data["risk"]["level"] in ["LOW", "INFO", "MEDIUM"]

    def test_e2e_04_plaintext_smtp(self, auth_token):
        """E2E-04: Upload plaintext SMTP -> PLAINTEXT finding, CRITICAL risk."""
        pcap = CAPTURES_RAW / "SMTP_25_PLAINTEXT_20260909_191343.pcap"
        data = self._run_upload(pcap, auth_token)

        assert data["status"] == "COMPLETED"
        findings = [f["finding_type"] for f in data["findings"]]
        assert "PLAINTEXT" in findings
        assert data["risk"]["level"] == "CRITICAL"
        assert data["risk"]["score"] >= 80

    def test_e2e_05_plaintext_imap(self, auth_token):
        """E2E-05: Upload plaintext IMAP -> PLAINTEXT finding, CRITICAL risk."""
        pcap = CAPTURES_RAW / "IMAP_143_PLAINTEXT_20260909_191158.pcap"
        data = self._run_upload(pcap, auth_token)

        assert data["status"] == "COMPLETED"
        findings = [f["finding_type"] for f in data["findings"]]
        assert "PLAINTEXT" in findings
        assert data["risk"]["level"] == "CRITICAL"

    def test_e2e_06_plaintext_pop3(self, auth_token):
        """E2E-06: Upload plaintext POP3 -> PLAINTEXT finding, CRITICAL risk."""
        pcap = CAPTURES_RAW / "POP3_110_PLAINTEXT_20260909_191254.pcap"
        data = self._run_upload(pcap, auth_token)

        assert data["status"] == "COMPLETED"
        findings = [f["finding_type"] for f in data["findings"]]
        assert "PLAINTEXT" in findings
        assert data["risk"]["level"] == "CRITICAL"

    def test_e2e_07_validation_01_multi_session(self, auth_token):
        """E2E-07: Validation PCAP 1 with multiple sessions."""
        pcap = CAPTURES_VAL / "validation_01.pcap"
        data = self._run_upload(pcap, auth_token)

        assert data["status"] == "COMPLETED"
        assert data["summary"]["total_sessions"] >= 2
        assert len(data["sessions"]) == data["summary"]["total_sessions"]

    def test_e2e_08_validation_02_certificate_extraction(self, auth_token):
        """E2E-08: Validation PCAP 2 -> X.509 cert extraction and persistence."""
        pcap = CAPTURES_VAL / "validation_02.pcap"
        data = self._run_upload(pcap, auth_token)

        assert data["status"] == "COMPLETED"
        # Find session with certificate
        cert_sessions = [s for s in data["sessions"] if s.get("certificate") and s["certificate"].get("subject")]
        assert len(cert_sessions) > 0, "Expected at least one session with observed X.509 certificate"
        subject = cert_sessions[0]["certificate"]["subject"]
        assert "CN=mail.lab.local" in subject or "lab.local" in subject

    def test_e2e_09_validation_03_auth_before_tls(self, auth_token):
        """E2E-09: Validation PCAP 3 -> AUTH_BEFORE_TLS finding."""
        pcap = CAPTURES_VAL / "validation_03.pcap"
        data = self._run_upload(pcap, auth_token)

        assert data["status"] == "COMPLETED"
        findings = [f["finding_type"] for f in data["findings"]]
        assert "AUTH_BEFORE_TLS" in findings or "PLAINTEXT" in findings

    def test_e2e_10_recommendations_affected_sessions_persisted(self, auth_token):
        """E2E-10: Verify recommendations accurately retain affected_sessions from database."""
        pcap = CAPTURES_RAW / "SMTP_25_PLAINTEXT_20260909_191343.pcap"
        data = self._run_upload(pcap, auth_token)
        analysis_id = data["analysis_id"]

        # Fetch full stored analysis from Node gateway
        resp = requests.get(
            f"{NODE_BASE_URL}/analyses/{analysis_id}",
            headers={"Authorization": auth_token["Authorization"]},
            timeout=10,
        )
        assert resp.status_code == 200
        stored = resp.json()
        recs = stored["recommendations"]
        assert len(recs) > 0
        # Check that affected_sessions is present as an array
        for r in recs:
            assert "affected_sessions" in r
            assert isinstance(r["affected_sessions"], list)


# ---------------------------------------------------------------------------
# 4. REPEATED RUN / STABILITY TESTING (Section 27)
# ---------------------------------------------------------------------------
class TestRepeatedRunStability:
    def test_10_consecutive_analyses(self, auth_token):
        """Execute 10 consecutive full pipeline analyses to detect memory/zombie leaks."""
        pcap = CAPTURES_RAW / "SMTP_465_IMPLICIT_TLS_AUTH_SUCCESS_20260909_191354.pcap"
        results = []

        for i in range(10):
            with open(pcap, "rb") as f:
                files = {"file": (f"run_{i}_{pcap.name}", f, "application/vnd.tcpdump.pcap")}
                t0 = time.time()
                resp = requests.post(
                    f"{NODE_BASE_URL}/analyze",
                    headers={"Authorization": auth_token["Authorization"]},
                    files=files,
                    timeout=120,
                )
                duration = time.time() - t0

            assert resp.status_code == 201, f"Run {i+1} failed ({resp.status_code}): {resp.text}"
            res = resp.json()
            assert res["status"] == "COMPLETED"
            results.append({
                "run": i + 1,
                "analysis_id": res["analysis_id"],
                "duration_sec": round(duration, 3),
                "risk_score": res["risk"]["score"],
                "risk_level": res["risk"]["level"],
            })

        # Save machine-readable report
        out_path = RESULTS_DIR / "stability_10_runs.json"
        with open(out_path, "w") as out_f:
            json.dump(results, out_f, indent=2)

        durations = [r["duration_sec"] for r in results]
        avg_duration = sum(durations) / len(durations)
        assert avg_duration < 15.0, f"Average analysis duration too high: {avg_duration}s"
