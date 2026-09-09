# SecureMailScope — Data Pipeline & Dataset Architecture

## Overview

This directory stores datasets and metadata used for training, validating, and evaluating the SecureMailScope ML Risk Scoring Model.

```
data/
├── raw/                      # Raw PCAP analysis JSON files
├── curated/                  # Reviewed analysis JSONs (real/ & synthetic/)
├── labels/                   # Ground-truth session labels & guidelines
├── processed/                # Training, validation, and test datasets
│   ├── real_dataset.csv      # Extracted from actual PCAP analysis JSONs
│   ├── synthetic_dataset.csv # 1,600 validated scenario-based sessions
│   ├── combined_dataset.csv  # Merged real and synthetic samples
│   ├── train.csv             # 70% stratified training split (~1,122 rows)
│   ├── validation.csv        # 15% stratified validation split (~241 rows)
│   ├── test.csv              # 15% stratified test split (~241 rows)
│   ├── dataset_quality_report.json
│   └── dataset_quality_report.txt
└── README.md                 # This file
```

---

## 1. REAL DATA vs CURATED SYNTHETIC DATA

The SecureMailScope dataset architecture explicitly distinguishes between three data sources via the `data_source` column:

1. **`REAL`**:
   - Manually captured or publicly collected real-world PCAPs from controlled lab or live mail environments.
   - Run through the full protocol, TLS, and certificate analysis engine.
   - Labels manually assigned and peer-reviewed.
   - Currently, real-world holdout data is limited (`INSUFFICIENT_REAL_HOLDOUT_DATA`).
2. **`CURATED_SYNTHETIC`**:
   - 1,600 scenario-based samples systematically generated across 27 distinct scenario families.
   - Covers all protocols (SMTP, IMAP, POP3) and all risk levels (LOW, MEDIUM, HIGH, CRITICAL).
   - Enforces domain rules and logical security consistency (e.g. no TLS features on plaintext).
   - Adds controlled random variation and non-leaking finding count overlap.
3. **`DEMO`**:
   - Initial 4-session capture used for sanity checking and contract verification.

> [!WARNING]
> **Data sources are never silently merged.** Evaluation reports separately whether holdout data is synthetic or real. Synthetic performance must NOT be claimed as real-world accuracy.

---

## 2. Why Synthetic Scenarios Are Used

Real-world mail PCAPs with known security vulnerabilities (such as active cleartext authentication before TLS, expired certificates, or ancient SSLv3 ciphers) are scarce and often contain sensitive credentials that cannot be committed to version control. 

Curated synthetic scenarios allow the ML module to:
- Learn all 4 risk classes with sufficient statistical support (400 per class).
- Encounter all supported protocols (SMTP, IMAP, POP3).
- Model realistic combinations of security attributes while strictly forbidding impossible combinations.
- Provide a reproducible benchmark (`random_state=42`).

> **Note on Class Distribution**:
> The class distribution is intentionally approximately balanced (400/400/400/400) for MVP model training and does not represent real-world security risk prevalence, where benign encrypted traffic typically dominates.

---

## 3. Logical Constraint Enforcement

Every synthetic sample is validated by `ml/training/dataset_validator.py`. A candidate row is rejected and regenerated if it violates any of the following domain rules:

1. **Protocol One-Hot**: Exactly one of `protocol_smtp`, `protocol_imap`, `protocol_pop3` must be 1.
2. **Encryption One-Hot**: Exactly one of `encryption_plaintext`, `encryption_starttls`, `encryption_implicit` must be 1.
3. **Plaintext Isolation**: Plaintext sessions cannot possess TLS or certificate features (must be `NaN`), and cannot have `tls_upgrade_failed = 1`.
4. **STARTTLS Consistency**: `tls_upgrade_failed = 1` requires `encryption_starttls = 1` and implies unobservable TLS/cert parameters.
5. **Implicit TLS Consistency**: `encryption_implicit = 1` forbids `auth_before_tls = 1` (TLS precedes application authentication) and `tls_upgrade_failed = 1`.
6. **Certificate Validity**: A certificate cannot be simultaneously `expired_cert = 1` and `not_yet_valid_cert = 1`.
7. **Non-Negative Counts**: `critical_count`, `high_count`, `medium_count`, `low_count` must be non-negative integers.
8. **Label Consistency**: LOW sessions forbid critical/high findings and major vulnerabilities; CRITICAL sessions require severe exposure (plaintext, auth before TLS, or critical finding); MEDIUM forbids critical exposure.

---

## 4. Preventing Finding Count Label Leakage

Finding counts (`critical_count`, `high_count`, `medium_count`, `low_count`) correlate with risk severity but do **not** deterministically encode the label. Controlled overlaps exist across adjacent classes:
- Both `HIGH` and `CRITICAL` can feature `high_count >= 1`.
- Both `MEDIUM` and `HIGH` can feature `medium_count >= 1`.
- `LOW` can feature low/info findings (`low_count >= 1`).
The model must evaluate the complete security posture rather than memorizing a single counter.

---

## 5. Train / Validation / Test Splitting

Dataset splitting follows strict statistical hygiene:
- **70% Training (`train.csv`)**: Used exclusively to fit the imputer and classifiers.
- **15% Validation (`validation.csv`)**: Used for model selection and comparing baselines (`DummyClassifier`, `LogisticRegression`, `RandomForestClassifier`).
- **15% Test (`test.csv`)**: Held out until final evaluation. Never touched during model fitting or tuning.

### Scenario Leakage Tracking:
Each sample carries a `scenario_family` metadata column (e.g. `HIGH_WEAK_CIPHER`, `CRIT_PLAINTEXT_TRAFFIC`). Overlap between splits is tracked and documented in `dataset_quality_report.json`.

---

## 6. CLI Commands

```powershell
# 1. Generate 1,600 validated synthetic samples
python -m ml.training.synthetic_generator --samples 1600 --random-state 42 --output data/processed/synthetic_dataset.csv

# 2. Validate any dataset
python -m ml.training.dataset_validator --input data/processed/synthetic_dataset.csv

# 3. Build real/demo dataset from PCAP analyses
python -m ml.training.dataset_builder --input data/curated --labels data/labels/session_labels.csv --output data/processed/real_dataset.csv --data-source DEMO

# 4. Combine real and synthetic datasets
python -m ml.training.dataset_builder --real data/processed/real_dataset.csv --synthetic data/processed/synthetic_dataset.csv --output data/processed/combined_dataset.csv

# 5. Split into train/val/test and generate quality reports
python -m ml.training.dataset_builder --split --input data/processed/combined_dataset.csv --train-output data/processed/train.csv --validation-output data/processed/validation.csv --test-output data/processed/test.csv --report data/processed/dataset_quality_report.json

# 6. Train model with baseline comparisons
python -m ml.training.train --train data/processed/train.csv --validation data/processed/validation.csv --output ml/artifacts

# 7. Evaluate chosen model on held-out test split
python -m ml.training.evaluate --test data/processed/test.csv --model ml/artifacts/risk_model.joblib --output ml/artifacts

# 8. Run inference on an analysis JSON
python -m ml.inference.predictor --analysis data/curated/demo-001.json --model-dir ml/artifacts
```

---

## 7. Model Limitations & Future Expansion Plan

### Limitations:
- The current model was trained predominantly on curated synthetic scenarios.
- The high evaluation accuracy reflects the model learning structured security archetypes, not real-world edge cases.
- Real-world holdout validation remains insufficient (`INSUFFICIENT_REAL_HOLDOUT_DATA`).

### Future Plan:
1. **PCAP Collection**: Continuously capture anonymized SMTP/IMAP/POP3 captures in enterprise test environments.
2. **Independent Label Review**: Use multi-analyst consensus to label real PCAP sessions.
3. **Real Holdout Benchmark**: Evaluate the trained model exclusively against `>= 100` real sessions without synthetic data.
4. **Active Learning**: Identify low-confidence or high-entropy real sessions and add them to the training dataset.
