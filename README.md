# SecureMailScope

SecureMailScope is an enterprise-grade security analysis and monitoring platform designed for inspecting, dissecting, and auditing email network traffic (SMTP, IMAP, and POP3). It combines deterministic cryptographic inspection, a **dual-model machine learning architecture** (Supervised Risk Assessment + Unsupervised Behavioral Anomaly Detection), actionable hardening recommendations, and a local **AI Security Copilot**.

---

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                             React 18 Frontend                               │
│        Live Telemetry • Stream Inspector • Anomaly Cards • AI Copilot       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / REST & Multipart
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Node.js API Gateway                              │
│         JWT Auth • Multer Ingestion • Zod Validation • PostgreSQL           │
└──────────────┬───────────────────────────────────────────────┬──────────────┘
               │                                               │
               ▼ POST /internal/analyze                        ▼ Local REST
┌──────────────────────────────────────────────┐ ┌────────────────────────────┐
│         Django Forensic Analysis Engine      │ │      Ollama AI Copilot     │
│                                              │ │      mailscope-sec:3b      │
│  • Passive PCAP Dissection (TShark/PyShark)  │ └────────────────────────────┘
│  • TCP Stream Reconstruction & Completeness  │
│  • TLS 1.0–1.3 & X.509 Certificate Profiler  │
│  • 10 Deterministic Security Rules           │
│  • Random Forest Risk Model (rf-v1)          │
│  • Isolation Forest Anomaly Model (if-v1)    │
│  • Actionable Remediation Generator          │
└──────────────────────────────────────────────┘
```

---

## Project Structure

A clean, modular monorepo architecture separating presentation, orchestration, forensics, and intelligence:

```text
SecureMailScope/
├── frontend/               # React 18 single-page application (Vite, Tailwind CSS, Lucide, jsPDF)
├── node-gateway/           # Node.js API Gateway, PostgreSQL persistence, and orchestration
├── analysis/               # Forensic analysis backend (packet dissection, rule engine, Isolation Forest)
├── ml/                     # Supervised machine learning module (Random Forest risk classifier, training pipelines)
├── recommendation/         # Remediation engine generating prioritized mitigation guidance
├── ollama/                 # Local AI Copilot configuration (Modelfile and automated setup script)
├── data/                   # Dataset pipelines, benchmark splits (train/val/test), and PCAP generators
├── docs/                   # System architecture specs, dataset design, and authoritative JSON contracts
├── tests/                  # Unified test matrix (contracts, e2e, integration, ml, parser, rules)
├── test-results/           # Benchmark reports and latency stability metrics
└── migrate.sql             # Relational database schema (8 PostgreSQL tables)
```

---

## Core Capabilities

### 1. Forensic Inspection & Rule Engine ([`analysis/`](file:///analysis/))
- **Passive PCAP Dissection**: Reconstructs TCP streams and tracks conversation state across SMTP, IMAP, and POP3 sessions using TShark and PyShark.
- **Cryptographic Profiling**: Evaluates TLS handshake parameters, cipher suite strengths, forward secrecy (PFS), and X.509 certificate chains.
- **10 Deterministic Security Rules**: Flags plaintext credentials, authentication before TLS, failed STARTTLS upgrades, deprecated TLS versions, weak ciphers/keys, expired certificates, and untrusted self-signed certificates.

### 2. Dual-Model Machine Learning ([`ml/`](file:///ml/) & [`analysis/anomaly_detection/`](file:///analysis/anomaly_detection/))
- **Random Forest (`rf-v1`)**: Supervised classifier evaluating a 19-feature vector to assign calibrated session risk tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Protected by strict domain guardrails that prevent downgrading critical deterministic findings.
- **Isolation Forest (`if-v1`)**: Unsupervised behavioral anomaly detector extracting 30 flow-level features (packet timing, client/server ratios, reset counts) to detect statistical deviations from learned normal traffic baselines.

### 3. API Gateway & Persistence ([`node-gateway/`](file:///node-gateway/))
- **Security Middleware**: Helmet security headers, global rate limiting, and bcrypt-hashed authentication.
- **Safe Ingestion**: Enforces strict extension allowlists (`.pcap`, `.pcapng`, `.cap`) and renames uploads with random UUIDs to eliminate path traversal vulnerabilities.
- **Isolated Stream Slicing**: Extracts individual TCP sessions into downloadable, standalone PCAPs using safe binary execution without shell interpolation.
- **Relational Storage**: Persists analysis metadata, stream telemetry, findings, and anomaly scores into PostgreSQL via [`migrate.sql`](file:///migrate.sql).

### 4. Interactive Analyst UI ([`frontend/`](file:///frontend/))
- **Live Forensics Dashboard**: Real-time posture scoring, interactive session tables, and protocol distribution charts.
- **Deep-Dive Stream Inspector**: View reconstructed conversational flows, Wireshark display filters (e.g., `tcp.stream == 0`), cryptographic attributes, and export session PCAPs.
- **Standards Auditing**: Validates traffic compliance against **RFC 8314**, **RFC 7525**, and **NIST SP 800-52r2**.
- **Audit Reporting**: Exports structured JSON data and auto-generates branded PDF audit reports client-side.

### 5. Local AI Security Copilot ([`ollama/`](file:///ollama/))
- Offline, privacy-preserving AI assistant powered by a customized model (`mailscope-sec:3b`).
- Formulates executive risk summaries, explains complex cryptographic findings, maps threats to MITRE ATT&CK / CWE identifiers, and generates copy-pasteable hardening directives for **Postfix**, **Dovecot**, and **Nginx**.

---

## Audit & Verification Matrix

All subsystems have been verified with end-to-end automated test suites:

| Subsystem | Suite | Results | Defensive Audit Highlights |
| :--- | :--- | :--- | :--- |
| **Frontend** | Vitest (`npm test`) | **70 / 70 passed** | Custom AST Markdown renderer (immune to XSS injection). |
| **Node Gateway** | Jest (`npm test`) | **104 / 104 passed** | Parameterized SQL queries (immune to SQLi); `execFile` prevents command injection. |
| **Python & ML** | Pytest (`python -m pytest tests/`) | **289 / 289 passed** | Deterministic guardrails enforce critical findings; robust synthetic edge-case generator. |
| **System Stability**| Multi-Run Benchmark | **10 / 10 passed** | Sub-second analysis latency (0.40s–0.80s per run) documented in `test-results/`. |

---

## Quick Start Guide

### Prerequisites
- **Node.js** v18+ & **npm**
- **Python** 3.11+
- **PostgreSQL** 14+
- *Optional*: **Wireshark/TShark** (for live PCAP dissection) and **Ollama** (for local AI Copilot)

---

### 1. Database Setup
Initialize the PostgreSQL schema:

```bash
psql -U postgres -d securemailscope -f migrate.sql
```
*(Or run `npm run migrate` inside `node-gateway/`)*

---

### 2. Node Gateway Setup
```bash
cd node-gateway
npm install
cp .env.example .env     # Configure DATABASE_URL and JWT_SECRET
npm run dev              # Runs on http://localhost:3000 (Mock Django enabled by default)
```

---

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev              # Runs on http://localhost:5173
```

---

### 4. Analysis Backend *(Optional for Live Capture Dissection)*
To run live PCAP dissection instead of the default mock mode:
```bash
cd analysis
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r ../ml/requirements.txt
python manage.py runserver 8000
```
*Set `USE_MOCK_DJANGO=false` in `node-gateway/.env` to connect.*

---

### 5. Local AI Copilot *(Optional)*
```cmd
cd ollama
setup_model.bat          # Pulls qwen2.5:3b and configures mailscope-sec:3b
```

---

## Running Test Suites

```bash
# Frontend Unit & Integration Tests (Vitest)
cd frontend && npm test

# API Gateway Tests (Jest)
cd node-gateway && npm test

# Python Forensics, ML & Rule Tests (Pytest)
python -m pytest tests/

# Manual ML Inference Demonstration
python test_manual.py
```

---

## Inter-Service API Contracts

All cross-service boundaries are strictly governed by formal JSON Schemas located in [`docs/contracts/`](file:///docs/contracts/):
- **[`node-django-request.json`](file:///docs/contracts/node-django-request.json)**: Gateway upload task dispatch schema.
- **[`django-analysis-response.json`](file:///docs/contracts/django-analysis-response.json)**: Forensic inspection results schema.
- **[`node-react-analysis-response.json`](file:///docs/contracts/node-react-analysis-response.json)**: Client-facing normalized response schema.
- **[`ml-feature-vector.json`](file:///docs/contracts/ml-feature-vector.json)**: Random Forest 19-feature vector contract.
- **[`isolation-forest-feature-vector.json`](file:///docs/contracts/isolation-forest-feature-vector.json)**: Isolation Forest 30-feature vector contract.

---

## Development & Contribution

- **Branching**: Branch off `main` using descriptive prefixes: `feature/*`, `bugfix/*`, `refactor/*`, `docs/*`.
- **Commits**: Follow the [Conventional Commits](https://www.conventionalcommits.org/) format (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`).
- **Pull Requests**: Direct pushes to `main` are restricted. All changes require review and passing automated tests.

---

## License

This project is licensed under the terms described in the [LICENSE](file:///LICENSE) file.
