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
├── anomaly_detection/     # Isolation Forest behavioral anomaly detection
│   ├── feature_schema.py   # 30-feature vector schema definition (if-features-v1)
│   ├── feature_extractor.py# Extracts protocol, TLS, cert & TCP flow metrics
│   ├── preprocessing.py    # RobustScaler & median imputation pipeline
│   ├── dataset_generator.py# Offline protocol-aware normal baseline & anomaly generator
│   ├── train_model.py      # Offline model training & evaluation script
│   ├── inference.py        # AnomalyPredictor runtime inference
│   ├── explanation.py      # Baseline quantile deviations & finding cross-references
│   ├── service.py          # Process-level singleton, session analysis & failure shielding
│   └── artifacts/          # Model bundles, fitted scalers & baseline stats
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

All unit and integration tests validate:
- Table-driven rule execution across positive, negative, and unknown/incomplete cases.
- TCP session stream separation and completeness categorization.
- Command extraction and authentication-before-TLS detection.
- End-to-end pipeline contract conformity against `docs/contracts/django-analysis-response.json`.
- Django REST API file upload validation, controlled error responses, and cleanup.
- Isolation Forest 30-feature extraction, preprocessing, inference, failure isolation, and pipeline integration.

---

## Isolation Forest Offline Training

The Isolation Forest behavioral anomaly detection model can be trained offline using the dedicated training pipeline:

```powershell
# From workspace root:
python analysis/anomaly_detection/train_model.py
```

This command:
1. Generates 2,000 protocol-aware normal baseline email communication sessions (SMTP, IMAP, POP3).
2. Generates held-out evaluation scenarios (300 normal, 500 controlled anomalies).
3. Fits the imputation and `RobustScaler` pipeline exclusively on normal training data.
4. Trains an `IsolationForest(n_estimators=200, contamination=0.05, random_state=42)`.
5. Computes ROC-AUC, precision, recall, confusion matrix, and false-positive rates on the held-out set.
6. Serializes model artifacts and baseline quantile statistics to `analysis/anomaly_detection/artifacts/`.

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
  - Returns: JSON response strictly matching `docs/contracts/django-analysis-response.json` (includes `anomaly_assessment` and per-session `anomaly`)

