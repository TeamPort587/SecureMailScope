# SecureMailScope System Architecture

## 1. High-Level Architecture Overview

SecureMailScope is an enterprise-grade offline network forensic inspection platform tailored for analyzing mail protocol traffic (SMTP, IMAP, POP3). It combines deterministic protocol/cryptographic rule inspection with a dual-model machine learning architecture:
1. **Random Forest (`rf-v1`):** Supervised risk assessment classifying session vulnerabilities into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
2. **Isolation Forest (`if-v1`):** Unsupervised behavioral anomaly detection isolating statistical outliers relative to learned normal email communication baselines.

```
+─────────────────────────────────────────────────────────────────────────────+
│                             React 18 Frontend                               │
│  Dashboard • Analysis Overview • Findings • Anomaly Cards • History View   │
+──────────────────────────────────────▲──────────────────────────────────────+
                                       │ HTTP / REST & Multipart
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
│                             Node.js Gateway                                 │
│  Multer File Upload • Zod Schema Validation • Express Routers • PostgreSQL  │
+──────────────────────────────────────▲──────────────────────────────────────+
                                       │ POST /internal/analyze
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
│                    Django REST Analysis Engine Backend                      │
│                                                                             │
│  [PCAP Parser]  (TShark / PyShark Adapter -> PacketRecords)                 │
│         │                                                                   │
│         ▼                                                                   │
│  [Session Engine]  (TCP 4-tuple stream reconstruction & completeness)       │
│         │                                                                   │
│         ▼                                                                   │
│  [Feature Extractor]  (Protocol, TLS & X.509 normalization -> SecurityProfile)│
│         │                                                                   │
│         ▼                                                                   │
│  [Rule Engine]  (10 Deterministic Security Rules -> Findings)               │
│         │                                                                   │
│         ├──────────────────────────────────────────┐                        │
│         ▼                                          ▼                        │
│  [Random Forest Risk Model]            [Isolation Forest Anomaly Model]     │
│  • 19 Canonical Features               • 30 Behavioral Flow Features        │
│  • Supervised Risk Tier                • Unsupervised Outlier Isolation     │
│  • Quality & Confidence Metrics        • Quantile Deviations & Explanations │
│         │                                          │                        │
│         └────────────────────┬─────────────────────┘                        │
│                              ▼                                              │
│            [Integration & Response Aggregator]                              │
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 2. End-to-End Data & Execution Flow

1. **PCAP Ingestion:** The client uploads a capture (`.pcap` or `.pcapng`) to the Node.js Gateway.
2. **Gateway Forwarding:** The Gateway validates file integrity and forwards the payload to the internal Django API endpoint `POST /internal/analyze`.
3. **Passive Dissection:** The `pcap_parser` module invokes TShark (with fallback to PyShark) to extract packet layers into strongly typed `PacketRecord` instances.
4. **Session Reconstruction:** The `session_engine` groups packets by TCP streams, identifies client/server endpoints, calculates packet counts, durations, and determines session capture completeness (`COMPLETE`, `PARTIAL`, `UNKNOWN`).
5. **Security Profiling:** The `feature_extraction` module inspects commands (HELO/EHLO, STARTTLS, AUTH), TLS handshakes (version, cipher suite, extensions), and X.509 certificates to produce normalized `SecurityProfile` objects.
6. **Deterministic Rule Evaluation:** The `rule_engine` evaluates 10 security rules (plaintext, auth before TLS, failed STARTTLS, deprecated TLS, weak ciphers, expired/untrusted certificates, weak keys, lack of PFS) to produce evidence-backed `Finding` instances.
7. **Dual-Model Inference:**
   - **Random Forest:** Extracts the canonical 19-feature vector, imputes missing values, and scores overall risk level and confidence.
   - **Isolation Forest:** Extracts a distinct 30-feature vector encompassing protocol flags, TLS parameters, certificate attributes, TCP flow dynamics (packet counts, client/server ratios, reset counts), and context counts. The model computes decision scores, outlier classifications (`ANOMALOUS` vs `WITHIN_BASELINE`), relative anomaly indices (0–100), and generates feature deviation explanations against saved baseline quantiles.
   - **Failure Isolation:** Any exception or missing artifact in Isolation Forest defaults safely to `MODEL_UNAVAILABLE` or `ANALYSIS_ERROR` without disrupting rule evaluations or Random Forest risk scoring.
8. **Response Aggregation & Normalization:** `pipeline.py` packages findings, session security profiles, Random Forest risk results, and Isolation Forest anomaly assessments into a unified JSON response adhering to `docs/contracts/django-analysis-response.json`.
9. **Persistence & Client Delivery:** The Node.js Gateway validates the response via Zod, persists analysis sessions and anomaly results into PostgreSQL (with transactional savepoint fault-tolerance), and serves the response to the React dashboard.

---

## 3. Machine Learning Models: Architectural Distinction

| Dimension | Random Forest (`rf-v1`) | Isolation Forest (`if-v1`) |
|---|---|---|
| **Learning Paradigm** | Supervised classification | Unsupervised anomaly isolation |
| **Question Answered** | "What is the security risk tier of this session given known vulnerabilities?" | "How statistically unusual is this session compared to normal baseline traffic?" |
| **Feature Vector** | 19 canonical features (`ml-feature-vector.json`) | 30 behavioral features (`isolation-forest-feature-vector.json`) |
| **Target Variable** | Categorical risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) | None (unlabeled baseline) |
| **Input Dependencies** | Risk flags, cipher tiers, rule finding counts | Flow dynamics, packet ratios, TLS/cert parameters, protocol context |
| **Output Interpretation** | Class probabilities & risk score (0–100) | Anomaly score, outlier status (`ANOMALOUS`), deviation explanation |
| **Coupling / Invariant** | Independent; does not alter anomaly scores | Strictly supplementary; does not alter risk tiers or finding generation |

---

## 4. Frontend & Component Hierarchy

- **Analysis Dashboard (`frontend/src/pages/Analysis.jsx`):**
  - **Overview Tab:** High-level summary, Risk score gauge, Anomaly Detection Card (`AnomalyDetectionCard.jsx`), Protocol breakdown, and Recent findings.
  - **Anomalies Tab:** Dedicated behavioral analysis dashboard with filtering (`All`, `Anomalous`, `Within Baseline`), anomaly score metrics, baseline deviation tables, and rule finding cross-references.
  - **Sessions Tab:** Reconstructed stream table with session inspection drawers (`SessionDetails.jsx`) displaying cryptographic profiles, certificate metadata, and individual behavioral anomaly assessments.
  - **Findings & Recommendations:** Full evidence panels and actionable hardening guidance.
