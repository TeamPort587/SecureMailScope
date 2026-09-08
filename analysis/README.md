# SecureMailScope Analysis Engine

The **Analysis Engine** is the offline forensic inspection backend for SecureMailScope. It ingests PCAP/PCAPNG captures, passively extracts observable packet features, reconstructs TCP sessions, detects email protocols (SMTP, IMAP, POP3), extracts TLS/cryptographic metadata and X.509 certificates, produces normalized `SecurityProfile` objects, evaluates deterministic security rules, and exposes an internal API for Node Gateway and downstream ML integration.

---

## Pipeline Architecture

```
PCAP / PCAPNG File
       │
       ▼
[pcap_parser]           Passive packet dissection via TShark JSON / PyShark adapter
       │
  PacketRecords
       │
       ▼
[session_engine]        Reconstructs streams by tcp.stream, client/server roles & completeness
       │
   Sessions
       │
       ▼
[feature_extraction]    Identifies protocols, STARTTLS/Implicit/Plaintext, TLS version/ciphers & certs
       │
 SecurityProfiles       Strongly-typed dataclass conforming to project schema
       │
       ▼
[rule_engine]           10 deterministic security rules producing evidence-backed Finding objects
       │
Findings + Evidence
       │
       ▼
[integration]           Aggregates multi-session findings, posture summaries & recommendations
       │
       ▼
[Django Internal API]   POST /internal/analyze matching docs/contracts/django-analysis-response.json
```

---

## Directory Structure

```text
analysis/
├── api/                    # Django REST Framework internal endpoints
│   ├── urls.py             # Route /internal/analyze and /health
│   └── views.py            # Multipart PCAP upload handler & error mapping
├── pcap_parser/            # Offline PCAP extraction backends
│   ├── parser.py           # Unified parse_pcap entrypoint
│   ├── tshark.py           # TShark JSON runner and layer extractor
│   └── pyshark_adapter.py  # PyShark fallback adapter
├── session_engine/         # TCP stream reconstruction
│   └── engine.py           # Stream grouping, completeness (COMPLETE/PARTIAL/UNKNOWN)
├── feature_extraction/     # Normalization into SecurityProfile
│   ├── certificate.py      # X.509 metadata extraction
│   ├── email_protocol.py   # Command parsing, auth-before-TLS & encryption mode
│   ├── extractor.py        # SecurityProfile assembler
│   ├── models.py           # Typed Python dataclasses (PacketRecord, Session, SecurityProfile, Finding)
│   └── tls.py              # Version mapping, cipher suite & PFS determination
├── rule_engine/            # Deterministic rule evaluation
│   ├── engine.py           # Rule orchestrator
│   ├── severity.py         # Severity and confidence constants
│   └── rules/              # Modular security rules
│       ├── auth_before_tls.py
│       ├── deprecated_tls.py
│       ├── expired_certificate.py
│       ├── failed_starttls.py
│       ├── not_yet_valid_certificate.py
│       ├── pfs.py
│       ├── plaintext.py
│       ├── self_signed.py
│       ├── weak_cipher.py
│       └── weak_key.py
├── integration/            # Pipeline orchestration
│   └── pipeline.py         # analyze_pcap function & summary calculations
├── sms_analysis/           # Django project configuration
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── tests/                  # Automated test suite (53+ tests)
│   ├── conftest.py
│   ├── test_api.py
│   ├── test_feature_extraction.py
│   ├── test_pipeline.py
│   ├── test_rules.py
│   └── test_session_engine.py
├── manage.py               # Django management utility
└── requirements.txt        # Pinned Python dependencies
```

---

## Prerequisites

- **Python**: 3.11+ (verified with Python 3.14 on Windows 11)
- **TShark / Wireshark**: 4.0+ must be installed and accessible in `PATH` or at default install paths. Verify with:
  ```powershell
  tshark -v
  ```

---

## Virtual Environment Setup

All analysis development must be executed inside the dedicated `.venv` virtual environment:

```powershell
# Activate on Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Install / update requirements
pip install -r analysis/requirements.txt
```

---

## Running the Automated Test Suite

Execute the complete pytest suite:

```powershell
.\.venv\Scripts\pytest.exe analysis/tests -v
```

All 53 unit and integration tests validate:
- Table-driven rule execution across positive, negative, and unknown/incomplete cases.
- TCP session stream separation and completeness categorization.
- Command extraction and authentication-before-TLS detection.
- End-to-end pipeline contract conformity against `docs/contracts/django-analysis-response.json`.
- Django REST API file upload validation, controlled error responses, and cleanup.

---

## Running the Django Analysis API

Start the internal analysis server:

```powershell
.\.venv\Scripts\python.exe analysis/manage.py runserver 0.0.0.0:8000
```

### Endpoints

- **Health Check**: `GET /health`
  - Returns `200 OK` with `{"status": "healthy", "service": "sms-analysis-engine"}`
- **Analyze Capture**: `POST /internal/analyze`
  - Consumes: `multipart/form-data` with `file=<PCAP_FILE>` (optional: `analysis_id`, `filename`)
  - Returns: JSON response strictly matching `docs/contracts/django-analysis-response.json`
