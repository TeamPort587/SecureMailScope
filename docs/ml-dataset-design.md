# SecureMailScope ML Dataset Design & Specification

## 1. Executive Summary

This document specifies the dataset architecture, domain constraints, scenario design, and evaluation methodology for the **SecureMailScope Machine Learning Risk Scoring Module**. The dataset is designed to train and evaluate models that classify individual email communication sessions into one of four security risk tiers: **`LOW`**, **`MEDIUM`**, **`HIGH`**, or **`CRITICAL`**.

---

## 2. Canonical 19 Features

The ML module consumes exactly 19 features per email session, structured into six logical groups:

| Index | Feature Name | Type | Range / Values | Description |
|---|---|---|---|---|
| **1** | `encryption_plaintext` | Binary | 0, 1 | 1 if session operated entirely in cleartext. |
| **2** | `encryption_starttls` | Binary | 0, 1 | 1 if STARTTLS / STLS was attempted or negotiated. |
| **3** | `encryption_implicit` | Binary | 0, 1 | 1 if implicit TLS port (e.g. 465, 993, 995) was used. |
| **4** | `deprecated_tls` | Binary | 0, 1, NaN | 1 if SSLv2, SSLv3, TLS 1.0, or TLS 1.1 was negotiated; NaN if TLS not observable. |
| **5** | `weak_cipher` | Binary | 0, 1, NaN | 1 if RC4, 3DES, DES, NULL, EXPORT, or MD5 was used; NaN if not observable. |
| **6** | `expired_cert` | Binary | 0, 1, NaN | 1 if server certificate expiration date preceded capture timestamp; NaN if no cert. |
| **7** | `not_yet_valid_cert` | Binary | 0, 1, NaN | 1 if certificate valid-from date is in the future; NaN if no cert. |
| **8** | `weak_key` | Binary | 0, 1, NaN | 1 if RSA key length < 2048 bits; NaN if no cert. |
| **9** | `auth_before_tls` | Binary | 0, 1 | 1 if authentication credentials were transmitted prior to TLS handshake. |
| **10** | `tls_upgrade_failed` | Binary | 0, 1, NaN | 1 if STARTTLS command failed or was rejected; NaN if no upgrade attempt. |
| **11** | `pfs_missing` | Binary | 0, 1, NaN | 1 if cipher suite lacks Ephemeral Diffie-Hellman (DHE/ECDHE); NaN if no TLS. |
| **12** | `self_signed` | Binary | 0, 1, NaN | 1 if server certificate is self-signed or untrusted CA; NaN if no cert. |
| **13** | `protocol_smtp` | Binary | 0, 1 | 1 if SMTP (port 25, 587, 465). |
| **14** | `protocol_imap` | Binary | 0, 1 | 1 if IMAP (port 143, 993). |
| **15** | `protocol_pop3` | Binary | 0, 1 | 1 if POP3 (port 110, 995). |
| **16** | `critical_count` | Count | Integer >= 0 | Number of CRITICAL severity findings associated with the session. |
| **17** | `high_count` | Count | Integer >= 0 | Number of HIGH severity findings. |
| **18** | `medium_count` | Count | Integer >= 0 | Number of MEDIUM severity findings. |
| **19** | `low_count` | Count | Integer >= 0 | Number of LOW severity findings. |

### Metadata Exclusions:
The dataset stores additional metadata columns:
- `analysis_id`
- `session_id`
- `scenario_id`
- `scenario_family`
- `data_source`
- `risk_label` (target variable)

> [!IMPORTANT]
> All metadata columns are strictly excluded from model feature inputs. Only the canonical 19 features are supplied to imputers and classifiers.

---

## 3. Scenario Families

Synthetic samples are generated from 27 distinct scenario families across all four risk classes:

### LOW Class (6 families):
1. `LOW_MODERN_TLS_PFS`: STARTTLS, modern TLS 1.2/1.3, strong cipher, PFS, valid cert, zero high/crit findings.
2. `LOW_IMPLICIT_MODERN_TLS`: IMPLICIT_TLS, modern TLS 1.2/1.3, strong cipher, PFS, valid cert.
3. `LOW_STARTTLS_UNOBSERVABLE_CERT`: STARTTLS, modern TLS, certificate unobservable due to capture cutoff.
4. `LOW_IMPLICIT_UNOBSERVABLE_CERT`: IMPLICIT_TLS, modern TLS, certificate unobservable.
5. `LOW_MODERN_TLS_CLEAN_WITH_INFO`: Modern TLS, clean session, low_count = 1 or 2 (benign findings).
6. `LOW_IMPLICIT_CLEAN_LOW_FINDING`: IMPLICIT_TLS, clean session, low_count = 1.

### MEDIUM Class (6 families):
1. `MED_SELF_SIGNED_CERT`: STARTTLS, modern TLS, self-signed certificate, medium_count >= 1.
2. `MED_MISSING_PFS`: STARTTLS, modern TLS, cipher lacks PFS, medium_count >= 1.
3. `MED_LIMITED_CERT_VISIBILITY`: STARTTLS, partial certificate parameters missing, medium_count >= 1.
4. `MED_MINOR_FINDINGS_COMBINED`: STARTTLS, combination of low and medium findings without severe flaw.
5. `MED_SELF_SIGNED_IMPLICIT`: IMPLICIT_TLS, modern TLS, self-signed cert.
6. `MED_PFS_MISSING_IMPLICIT`: IMPLICIT_TLS, modern TLS, missing PFS.

### HIGH Class (9 families):
1. `HIGH_DEPRECATED_TLS`: Deprecated TLS version (SSLv3/TLS 1.0/TLS 1.1), high_count >= 1.
2. `HIGH_WEAK_CIPHER`: Obsolete cipher (RC4, 3DES, DES), high_count >= 1.
3. `HIGH_EXPIRED_CERT`: Certificate past expiration date, high_count >= 1.
4. `HIGH_NOT_YET_VALID_CERT`: Certificate validity starts in future, high_count >= 1.
5. `HIGH_WEAK_KEY`: RSA key < 2048 bits, high_count >= 1.
6. `HIGH_FAILED_STARTTLS`: STARTTLS upgrade rejected / failed, high_count >= 1.
7. `HIGH_DEPRECATED_AND_WEAK_CIPHER`: Both deprecated protocol and weak cipher active.
8. `HIGH_WEAK_KEY_AND_EXPIRED_CERT`: Multiple certificate flaws.
9. `HIGH_PFS_AND_SELF_SIGNED_MULTIPLE`: Combination of missing PFS, self-signed cert, and multiple medium findings.

### CRITICAL Class (6 families):
1. `CRIT_PLAINTEXT_TRAFFIC`: Unencrypted plaintext email traffic, critical_count >= 1.
2. `CRIT_PLAINTEXT_WITH_AUTH`: Plaintext mail session transmitting credentials in the clear.
3. `CRIT_STARTTLS_AUTH_BEFORE_TLS`: Client sends AUTH before negotiating STARTTLS.
4. `CRIT_STARTTLS_AUTH_EARLY_AND_FAILED_UPGRADE`: Cleartext auth followed by failed TLS upgrade.
5. `CRIT_PLAINTEXT_MULTIPLE_EXPOSURES`: Plaintext traffic with multiple severe policy breaches.
6. `CRIT_STARTTLS_AUTH_EARLY_WEAK_CIPHER`: Cleartext auth combined with obsolete cipher.

---

## 4. Valid vs Invalid Combinations (Constraint Rules)

The constraint validator (`ml/training/dataset_validator.py`) programmatically enforces domain rules:

| Condition | Rule | Rationale |
|---|---|---|
| `encryption_plaintext = 1` | TLS features (`deprecated_tls`, `weak_cipher`, `pfs_missing`) **MUST be NaN**. | No TLS handshake occurred. |
| `encryption_plaintext = 1` | Cert features (`expired_cert`, `weak_key`, etc.) **MUST be NaN**. | No certificate was presented. |
| `encryption_plaintext = 1` | `tls_upgrade_failed` **MUST NOT be 1**. | No upgrade was attempted. |
| `encryption_implicit = 1` | `auth_before_tls` **MUST be 0**. | In implicit TLS, TLS is established on connect before application authentication. |
| `encryption_implicit = 1` | `tls_upgrade_failed` **MUST be 0**. | Implicit TLS does not use upgrade commands. |
| `expired_cert = 1` | `not_yet_valid_cert` **CANNOT be 1**. | A certificate cannot be expired and not yet valid at the same timestamp. |
| Protocol One-Hot | Sum of `protocol_smtp`, `protocol_imap`, `protocol_pop3` **MUST be exactly 1**. | Mutually exclusive protocols. |
| Encryption One-Hot | Sum of `encryption_plaintext`, `encryption_starttls`, `encryption_implicit` **MUST be exactly 1**. | Mutually exclusive modes. |
| Finding Counts | `critical_count`, `high_count`, `medium_count`, `low_count` **MUST be >= 0**. | Counts cannot be negative. |
| Risk: `LOW` | `critical_count == 0` and `high_count == 0` and zero major vulnerabilities. | Benign sessions cannot contain severe vulnerabilities. |
| Risk: `MEDIUM` | `critical_count == 0` and `encryption_plaintext == 0` and `auth_before_tls == 0`. | Moderate risk cannot contain cleartext exposure. |

---

## 5. Unknown / Missing Value Policy (NaN)

- **`1`**: Confirmed true / present.
- **`0`**: Confidently false / absent.
- **`NaN`**: Unavailable, unobservable, or logically inapplicable.

> [!CAUTION]
> Unknown values are **never** silently converted to 0. An unobservable certificate does not imply a valid certificate. During training and inference, `SimpleImputer(strategy='most_frequent', add_indicator=True)` preserves missingness indicators for tree splits.

---

## 6. Finding Count Non-Leakage Design

Finding counts correlate with risk severity but do **not** deterministically dictate labels:
- **`CRITICAL`** sessions average 1.7 critical findings, but also average 0.9 high findings and 0.8 medium findings.
- **`HIGH`** sessions average 1.4 high findings, but also average 1.1 medium findings and 0.9 low findings.
- **`MEDIUM`** sessions average 1.5 medium findings and 1.1 low findings.
- **`LOW`** sessions average 0.7 low findings and 0 medium/high/critical findings.

Because `high_count >= 1` appears in both HIGH and CRITICAL, and `medium_count >= 1` appears in both MEDIUM and HIGH, the model cannot trivially predict risk using counts alone.

---

## 7. Train / Validation / Test Splitting Strategy

The combined dataset (1,604 samples) is split into:
- **`train.csv`**: 1,122 samples (70%)
- **`validation.csv`**: 241 samples (15%)
- **`test.csv`**: 241 samples (15%)

### Splitting Hygiene:
1. **Stratification**: Splitting is stratified across `risk_label` to preserve exact class balances.
2. **Zero ID Overlap**: Verified by `test_no_overlapping_sessions_between_splits`.
3. **Strict Isolation**: Feature imputers are fitted solely on `train.csv`.
4. **Validation Selection**: Baseline comparison and model selection are evaluated exclusively on `validation.csv`.
5. **Single Test Run**: `test.csv` is evaluated exactly once after model selection.

---

## 8. Baseline Model Comparison & Selection

Validation split comparison (`ml/artifacts/model_comparison.json`):

| Model | Accuracy | F1 Macro | Precision Macro | Recall Macro |
|---|---|---|---|---|
| `DummyClassifier` | 27.80% | 0.2783 | 0.2815 | 0.2777 |
| `LogisticRegression` | 100.00% | 1.0000 | 1.0000 | 1.0000 |
| **`RandomForestClassifier`** | **100.00%** | **1.0000** | **1.0000** | **1.0000** |

`RandomForestClassifier` was selected as the final production model due to its non-linear decision boundary capabilities and robust handling of missing indicator features.

---

## 9. Limitations & Real Data Expansion Plan

1. **Synthetic Bias**: The dataset consists predominantly of curated synthetic scenarios (1,600 synthetic, 4 demo). The 100% test accuracy reflects the model's mastery of the scenario logic rather than real-world traffic complexity.
2. **Holdout Status**: Flagged as `INSUFFICIENT_REAL_HOLDOUT_DATA`.
3. **Expansion Roadmap**:
   - Collect at least 100 diverse enterprise mail PCAPs.
   - Run PCAPs through the Django analysis pipeline.
   - Establish multi-analyst consensus on session risk labels.
   - Benchmark models against real holdout captures without synthetic training assistance.
