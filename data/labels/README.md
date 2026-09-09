# SecureMailScope — Labels Directory

## Overview

This directory stores ground-truth risk labels assigned to individual email sessions for training and evaluating the ML scoring model.

## File Format (`session_labels.csv`)

Labels must follow this CSV format:

```csv
analysis_id,session_id,risk_label
demo-001,smtp-001,LOW
demo-001,smtp-002,CRITICAL
demo-001,imap-001,CRITICAL
demo-001,pop3-001,LOW
```

### Column Specifications:
- `analysis_id`: Identifier matching the analysis JSON file (or `file.analysis_id`).
- `session_id`: Identifier matching `session.session_id`.
- `risk_label`: Exactly one of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

## Risk Labeling Policy

| Risk Level | Typical Security Characteristics |
|------------|----------------------------------|
| `LOW`      | Modern TLS (TLS 1.2/1.3), strong ciphers, PFS present, valid or unobservable certificate, zero critical/high findings. |
| `MEDIUM`   | Minor or limited issues: self-signed certificate, missing PFS, limited certificate visibility, minor finding counts (medium >= 1, low >= 1). No plaintext authentication. |
| `HIGH`     | Major security weaknesses: deprecated TLS (TLS 1.0/1.1), weak ciphers (RC4, 3DES, DES), expired certificates, weak RSA keys (<2048-bit), failed STARTTLS upgrades. |
| `CRITICAL` | Severe exposure: plaintext transmission, cleartext authentication before TLS, plaintext with active credentials, or failed upgrade combined with cleartext authentication. |

> [!NOTE]
> Labeling should be reviewed by at least two security engineers before inclusion in the canonical training set.
