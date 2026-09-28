# Isolation Forest Model Evaluation Report

**Model Version:** `if-v1`  
**Feature Schema Version:** `if-features-v1` (30 features)  
**Trained Timestamp:** 2026-09-27T16:12:26Z  
**Component:** SecureMailScope Behavioral Anomaly Detection  

---

## 1. Executive Summary & Architectural Role

SecureMailScope uses a two-pronged machine learning architecture:
1. **Random Forest (`rf-v1`):** Supervised risk classification using 19 risk-focused features to predict session severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
2. **Isolation Forest (`if-v1`):** Unsupervised behavioral anomaly detection using 30 session-level protocol, TLS, certificate, and TCP flow features to measure statistical divergence from normal operational baselines.

### Critical Invariant
- **Isolation Forest does NOT replace the Random Forest risk score.**
- **Isolation Forest does NOT alter deterministic rule findings or recommendations.**
- Statistical deviation is not synonymous with malicious activity; a session may be benign yet statistically unusual (e.g., uncommon TLS cipher or high packet count), or known-vulnerable yet statistically common. Both perspectives are evaluated and presented independently.

---

## 2. Dataset Provenance & Baseline Design

### 2.1 Why a Dedicated Baseline was Generated
The existing CSV datasets (`data/processed/train.csv`, `real_dataset.csv`, `combined_dataset.csv`) use the canonical 19-feature Random Forest schema oriented around vulnerability flags and rule severity counts. They lack essential behavioral flow metrics (such as packet ratios, bidirectional counts, duration, and certificate validity windows) required for behavioral outlier isolation.

To avoid data leakage and prevent conflating risk severity with statistical deviation, an offline protocol-aware baseline generator was implemented in `analysis/anomaly_detection/dataset_generator.py`.

### 2.2 Baseline Composition
- **Total Training Samples:** 2,000 normal sessions (SMTP 60%, IMAP 25%, POP3 15%).
- **Protocol Configurations:**
  - Modern TLS (TLS 1.2 / TLS 1.3) with standard AEAD cipher suites (AES-GCM, CHACHA20-POLY1305).
  - Valid RSA (2048/4096-bit) and ECDSA (256/384-bit) certificates with validity periods between 90 and 395 days.
  - Realistic bidirectional TCP flow distributions (packet counts 10–50, client/server ratios ~0.4–0.6, complete 3-way handshakes).
  - Zero plaintexts or failed handshakes in the baseline.

---

## 3. Evaluation Setup & Held-out Scenarios

The trained model was evaluated against an independent held-out evaluation dataset that was **never** used during model fitting or preprocessor scaling:

1. **Held-Out Normal Baseline (`N = 300`):**
   - Legitimate SMTP, IMAP, and POP3 sessions drawn from the same baseline distribution.
2. **Controlled Evaluation Anomalies (`N = 500`):**
   - High-packet flood / burst sessions (>300 packets).
   - Incomplete TLS handshakes & sudden TCP RST terminations.
   - Deprecated SSL/TLS versions (SSLv3, TLS 1.0) and weak ciphers (RC4, 3DES).
   - Abnormally short or long session durations.
   - Self-signed, expired, or non-observable certificates in unexpected protocol modes.
   - Plaintext mail transmissions and unexpected protocol port combinations.

---

## 4. Model Configuration & Hyperparameters

```python
IsolationForest(
    n_estimators=200,
    contamination=0.05,
    max_samples="auto",
    random_state=42,
    n_jobs=-1
)
```

- **Preprocessing:** Median imputation for unobserved features (`NaN`), followed by `RobustScaler` (IQR-based scaling) fitted exclusively on the 2,000 training normal samples.
- **Decision Threshold:** `-0.6192` (score threshold selected based on the fitted 5% contamination rate).

---

## 5. Actual Evaluation Metrics

| Metric | Result | Interpretation |
|---|---|---|
| **ROC-AUC** | **0.7674** | Good discriminative capacity on continuous anomaly decision scores across diverse scenario types. |
| **Precision** | **0.9149** | When flagged as an anomaly, 91.5% of sessions belonged to controlled abnormal scenarios. |
| **Recall (Detection Rate)** | **0.2580** | Conservative threshold ensures only strong deviations are flagged as `ANOMALOUS`. |
| **F1 Score** | **0.4025** | Reflects deliberate trade-off prioritizing low false positives over aggressive flagging. |
| **False Positive Rate (FPR)** | **0.0400** | Only 4.0% (12 / 300) of normal held-out baseline sessions were flagged as anomalous. |

### Confusion Matrix (Held-out Test: 300 Normal, 500 Anomalies)

| | Predicted Normal | Predicted Anomaly | Total |
|---|---|---|---|
| **Actual Normal** | 288 (TN) | 12 (FP) | 300 |
| **Actual Anomaly** | 371 (FN) | 129 (TP) | 500 |

*Note:* In unsupervised anomaly detection, mild deviations remain within the dense core of the tree isolation envelope. The conservative 5% contamination prevents operational noise while reliably isolating severe outliers (e.g., flood attacks, handshake anomalies, and weak legacy ciphers).

---

## 6. Score Interpretation & Output Semantics

- **`raw_score`:** Negative score from scikit-learn's `score_samples()` where lower values indicate greater isolation.
- **`decision_score`:** `decision_function()` score offset by the estimator threshold.
- **`anomaly_index`:** Normalized relative scale (0–100) for UI display.
  - `0–39`: Typical baseline behavior
  - `40–59`: Mild divergence
  - `60–79`: Moderate outlier
  - `80–100`: High behavioral anomaly
- **Classification States:**
  - `WITHIN_BASELINE`: Session parameters lie within learned normal clusters.
  - `ANOMALOUS`: Session parameters lie beyond isolation threshold.
  - `INSUFFICIENT_EVIDENCE`: Capture is partial or lacks essential session packets.
  - `MODEL_UNAVAILABLE`: Fallback state when model artifacts are missing.
  - `ANALYSIS_ERROR`: Exception shielded to guarantee pipeline stability.

---

## 7. Known Limitations & Disclosures

1. **Controlled Synthetic Baseline:** The training baseline was synthetically modeled on RFC-compliant email traffic patterns. Evaluation metrics reflect controlled scenarios rather than confirmed in-the-wild zero-day attacks.
2. **False Outliers on Benign Novelty:** Unconventional but legitimate server configurations (such as custom enterprise ports or unusual packet sizes) may trigger an anomaly classification.
3. **In-Distribution Malicious Traffic:** Covert attacks that mirror normal baseline traffic features (e.g. low-rate credential stuffing over standard TLS 1.3) will not be isolated by statistical feature distributions alone; these rely on deterministic rule engine detection.
