"""
Isolation Forest — Synthetic Baseline & Evaluation Dataset Generator
=====================================================================

Generates protocol-aware synthetic session profiles for:
1. Normal baseline training data (Stage 1)
2. Controlled anomaly evaluation data (Stage 2)

Uses deterministic seeds for reproducibility.
Does NOT overwrite existing project datasets.
"""

from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from analysis.anomaly_detection.feature_schema import (
    ALL_IF_FEATURES,
    IF_FEATURE_COUNT,
    IF_SCHEMA_VERSION,
)

logger = logging.getLogger(__name__)

NaN = float("nan")


def _random_protocol(rng: np.random.Generator) -> Tuple[float, float, float]:
    """Generate protocol one-hot with weighted distribution."""
    proto = rng.choice(["SMTP", "IMAP", "POP3"], p=[0.5, 0.3, 0.2])
    return (
        1.0 if proto == "SMTP" else 0.0,
        1.0 if proto == "IMAP" else 0.0,
        1.0 if proto == "POP3" else 0.0,
    )


def generate_normal_baseline(
    n_samples: int = 2000,
    random_state: int = 42,
) -> Tuple[np.ndarray, List[str]]:
    """Generate synthetic normal email/TLS session feature vectors.

    Returns (feature_matrix, scenario_labels).
    """
    rng = np.random.default_rng(random_state)
    samples: List[List[float]] = []
    labels: List[str] = []

    for i in range(n_samples):
        smtp, imap, pop3 = _random_protocol(rng)

        # Encryption mode — mostly encrypted
        enc_choice = rng.choice(
            ["STARTTLS", "IMPLICIT_TLS", "PLAINTEXT_RARE"],
            p=[0.45, 0.50, 0.05],
        )
        if enc_choice == "STARTTLS":
            plain, starttls, implicit = 0.0, 1.0, 0.0
            upgrade_adv = 1.0
            upgrade_req = 1.0
            upgrade_succ = 1.0
        elif enc_choice == "IMPLICIT_TLS":
            plain, starttls, implicit = 0.0, 0.0, 1.0
            upgrade_adv = NaN  # Not applicable
            upgrade_req = NaN
            upgrade_succ = 1.0
        else:
            # Rare plaintext in normal baseline (some legacy systems)
            plain, starttls, implicit = 1.0, 0.0, 0.0
            upgrade_adv = 0.0
            upgrade_req = 0.0
            upgrade_succ = 0.0

        auth_before_tls = 0.0  # Normal: auth AFTER TLS

        # TLS version — mostly modern
        if enc_choice != "PLAINTEXT_RARE":
            tls_ver = rng.choice([4.0, 5.0], p=[0.4, 0.6])  # TLS 1.2 or 1.3
            cipher_str = 2.0  # strong
            pfs = 1.0
            tls_incomplete = 0.0
        else:
            tls_ver = NaN
            cipher_str = NaN
            pfs = NaN
            tls_incomplete = 0.0  # No TLS expected

        # Certificate — mostly visible with standard params
        if enc_choice != "PLAINTEXT_RARE":
            cert_vis = 1.0
            cert_key_size = rng.choice([2048.0, 4096.0], p=[0.6, 0.4])
            cert_self_signed = 0.0  # Normal: CA-signed
            cert_validity = rng.uniform(30.0, 365.0)  # 30 days to 1 year remaining
            cert_rsa = rng.choice([1.0, 0.0], p=[0.7, 0.3])
            cert_ec = 1.0 - cert_rsa
        else:
            cert_vis = 0.0
            cert_key_size = NaN
            cert_self_signed = NaN
            cert_validity = NaN
            cert_rsa = NaN
            cert_ec = NaN

        # TCP session behavior — normal ranges
        pkt_count = rng.integers(8, 120)
        duration = rng.uniform(0.1, 15.0)
        client_pkt = int(pkt_count * rng.uniform(0.3, 0.55))
        server_pkt = pkt_count - client_pkt
        pkt_ratio = client_pkt / max(pkt_count, 1)
        reset_count = 0.0  # Normal: no resets
        complete = 1.0  # Normal: complete sessions

        # Findings — normal: 0 or minimal
        finding_count = 0.0
        high_sev = 0.0
        med_sev = 0.0

        vec = [
            smtp, imap, pop3,
            plain, starttls, implicit,
            upgrade_adv, upgrade_req, upgrade_succ,
            auth_before_tls,
            tls_ver, cipher_str, pfs, tls_incomplete,
            cert_vis, cert_key_size, cert_self_signed, cert_validity,
            cert_rsa, cert_ec,
            float(pkt_count), round(duration, 4),
            float(client_pkt), float(server_pkt),
            round(pkt_ratio, 4), reset_count, complete,
            finding_count, high_sev, med_sev,
        ]
        assert len(vec) == IF_FEATURE_COUNT
        samples.append(vec)
        labels.append("NORMAL")

    return np.array(samples), labels


def generate_anomaly_scenarios(
    n_samples: int = 500,
    random_state: int = 99,
) -> Tuple[np.ndarray, List[str]]:
    """Generate controlled anomaly scenarios for evaluation.

    Each scenario applies COMPOUND deviations (multiple features)
    to ensure the anomaly is distinguishable in a multivariate
    Isolation Forest feature space.

    Returns (feature_matrix, scenario_labels).
    """
    rng = np.random.default_rng(random_state)
    samples: List[List[float]] = []
    labels: List[str] = []

    scenario_types = [
        ("DEPRECATED_TLS_WEAK_CIPHER", 0.12),
        ("PLAINTEXT_AUTH_EXPOSED", 0.12),
        ("SELF_SIGNED_EXPIRED_CERT", 0.10),
        ("HIGH_VOLUME_INCOMPLETE", 0.10),
        ("RESET_STORM_SHORT", 0.10),
        ("LEGACY_WEAK_EVERYTHING", 0.10),
        ("HANDSHAKE_FAILURE_CASCADE", 0.10),
        ("MICRO_SESSION_ANOMALY", 0.10),
        ("ASYMMETRIC_TRAFFIC", 0.08),
        ("MULTI_FINDING_SESSION", 0.08),
    ]

    for scenario, fraction in scenario_types:
        count = max(1, int(n_samples * fraction))
        for _ in range(count):
            smtp, imap, pop3 = _random_protocol(rng)

            if scenario == "DEPRECATED_TLS_WEAK_CIPHER":
                # Compound: old TLS + weak cipher + no PFS + moderate key + findings
                plain, starttls, implicit = 0.0, 1.0, 0.0
                upgrade_adv, upgrade_req, upgrade_succ = 1.0, 1.0, 1.0
                auth_before_tls = 0.0
                tls_ver = rng.choice([0.0, 1.0, 2.0])  # SSLv2/SSLv3/TLS1.0
                cipher_str = 0.0  # weak
                pfs = 0.0  # no PFS
                tls_incomplete = 0.0
                cert_vis = 1.0
                cert_key_size = rng.choice([1024.0, 512.0])
                cert_self_signed = rng.choice([0.0, 1.0])
                cert_validity = rng.uniform(10.0, 200.0)
                cert_rsa = 1.0
                cert_ec = 0.0
                pkt_count = rng.integers(10, 60)
                duration = rng.uniform(0.5, 8.0)
                client_pkt = int(pkt_count * rng.uniform(0.35, 0.50))
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = 0.0
                complete = 1.0
                finding_count = rng.integers(2, 5)
                high_sev = rng.integers(1, 3)
                med_sev = rng.integers(0, 2)

            elif scenario == "PLAINTEXT_AUTH_EXPOSED":
                # Compound: plaintext + auth before TLS + no cert + findings
                plain, starttls, implicit = 1.0, 0.0, 0.0
                upgrade_adv, upgrade_req, upgrade_succ = 0.0, 0.0, 0.0
                auth_before_tls = 1.0
                tls_ver = NaN
                cipher_str = NaN
                pfs = NaN
                tls_incomplete = 0.0
                cert_vis = 0.0
                cert_key_size = NaN
                cert_self_signed = NaN
                cert_validity = NaN
                cert_rsa = NaN
                cert_ec = NaN
                pkt_count = rng.integers(5, 40)
                duration = rng.uniform(0.1, 5.0)
                client_pkt = int(pkt_count * rng.uniform(0.3, 0.6))
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = 0.0
                complete = rng.choice([0.0, 1.0])
                finding_count = rng.integers(2, 6)
                high_sev = rng.integers(1, 4)
                med_sev = 0.0

            elif scenario == "SELF_SIGNED_EXPIRED_CERT":
                # Compound: self-signed + expired + weak key + findings
                plain, starttls, implicit = 0.0, 1.0, 0.0
                upgrade_adv, upgrade_req, upgrade_succ = 1.0, 1.0, 1.0
                auth_before_tls = 0.0
                tls_ver = rng.choice([3.0, 4.0])
                cipher_str = rng.choice([1.0, 2.0])
                pfs = rng.choice([0.0, 1.0])
                tls_incomplete = 0.0
                cert_vis = 1.0
                cert_key_size = rng.choice([1024.0, 768.0, 512.0])
                cert_self_signed = 1.0
                cert_validity = rng.uniform(-500.0, -10.0)  # Expired
                cert_rsa = 1.0
                cert_ec = 0.0
                pkt_count = rng.integers(10, 60)
                duration = rng.uniform(0.5, 8.0)
                client_pkt = int(pkt_count * rng.uniform(0.35, 0.50))
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = 0.0
                complete = 1.0
                finding_count = rng.integers(2, 4)
                high_sev = rng.integers(1, 3)
                med_sev = rng.integers(1, 2)

            elif scenario == "HIGH_VOLUME_INCOMPLETE":
                # Compound: very high packet count + incomplete + resets + long duration
                plain, starttls, implicit = 0.0, 1.0, 0.0
                upgrade_adv, upgrade_req, upgrade_succ = 1.0, 1.0, 0.0
                auth_before_tls = 0.0
                tls_ver = 4.0
                cipher_str = 2.0
                pfs = 1.0
                tls_incomplete = 1.0
                cert_vis = 0.0
                cert_key_size = NaN
                cert_self_signed = NaN
                cert_validity = NaN
                cert_rsa = NaN
                cert_ec = NaN
                pkt_count = rng.integers(500, 10000)
                duration = rng.uniform(60.0, 600.0)
                client_pkt = int(pkt_count * rng.uniform(0.1, 0.3))
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = rng.uniform(5.0, 30.0)
                complete = 0.0
                finding_count = rng.integers(1, 3)
                high_sev = 1.0
                med_sev = 0.0

            elif scenario == "RESET_STORM_SHORT":
                # Compound: many resets + very short duration + incomplete + few packets
                plain, starttls, implicit = 0.0, 1.0, 0.0
                upgrade_adv, upgrade_req, upgrade_succ = 1.0, 1.0, 0.0
                auth_before_tls = 0.0
                tls_ver = NaN
                cipher_str = NaN
                pfs = NaN
                tls_incomplete = 1.0
                cert_vis = 0.0
                cert_key_size = NaN
                cert_self_signed = NaN
                cert_validity = NaN
                cert_rsa = NaN
                cert_ec = NaN
                pkt_count = rng.integers(2, 8)
                duration = rng.uniform(0.001, 0.1)
                client_pkt = max(1, pkt_count // 2)
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = rng.uniform(10.0, 100.0)
                complete = 0.0
                finding_count = rng.integers(1, 3)
                high_sev = 1.0
                med_sev = 0.0

            elif scenario == "LEGACY_WEAK_EVERYTHING":
                # Compound: old TLS + weak cipher + no PFS + self-signed + weak key + auth before
                plain, starttls, implicit = 0.0, 1.0, 0.0
                upgrade_adv, upgrade_req, upgrade_succ = 1.0, 1.0, 1.0
                auth_before_tls = 1.0
                tls_ver = rng.choice([0.0, 1.0, 2.0])
                cipher_str = 0.0
                pfs = 0.0
                tls_incomplete = 0.0
                cert_vis = 1.0
                cert_key_size = rng.choice([512.0, 768.0, 1024.0])
                cert_self_signed = 1.0
                cert_validity = rng.uniform(-200.0, 30.0)
                cert_rsa = 1.0
                cert_ec = 0.0
                pkt_count = rng.integers(5, 30)
                duration = rng.uniform(0.1, 3.0)
                client_pkt = int(pkt_count * rng.uniform(0.3, 0.5))
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = 0.0
                complete = rng.choice([0.0, 1.0])
                finding_count = rng.integers(3, 8)
                high_sev = rng.integers(2, 5)
                med_sev = rng.integers(1, 3)

            elif scenario == "HANDSHAKE_FAILURE_CASCADE":
                # Compound: TLS incomplete + upgrade failed + resets
                plain, starttls, implicit = 0.0, 1.0, 0.0
                upgrade_adv, upgrade_req, upgrade_succ = 1.0, 1.0, 0.0
                auth_before_tls = rng.choice([0.0, 1.0])
                tls_ver = NaN
                cipher_str = NaN
                pfs = NaN
                tls_incomplete = 1.0
                cert_vis = 0.0
                cert_key_size = NaN
                cert_self_signed = NaN
                cert_validity = NaN
                cert_rsa = NaN
                cert_ec = NaN
                pkt_count = rng.integers(3, 15)
                duration = rng.uniform(0.01, 1.0)
                client_pkt = max(1, int(pkt_count * rng.uniform(0.4, 0.7)))
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = rng.uniform(1.0, 10.0)
                complete = 0.0
                finding_count = rng.integers(1, 4)
                high_sev = rng.integers(1, 3)
                med_sev = 0.0

            elif scenario == "MICRO_SESSION_ANOMALY":
                # Compound: extremely few packets + near-zero duration + incomplete
                plain, starttls, implicit = rng.choice([1.0, 0.0]), rng.choice([0.0, 1.0]), 0.0
                upgrade_adv = rng.choice([0.0, 1.0])
                upgrade_req = 0.0
                upgrade_succ = 0.0
                auth_before_tls = 0.0
                tls_ver = NaN
                cipher_str = NaN
                pfs = NaN
                tls_incomplete = 1.0 if starttls == 1.0 else 0.0
                cert_vis = 0.0
                cert_key_size = NaN
                cert_self_signed = NaN
                cert_validity = NaN
                cert_rsa = NaN
                cert_ec = NaN
                pkt_count = rng.integers(1, 4)
                duration = rng.uniform(0.0, 0.05)
                client_pkt = max(1, pkt_count // 2)
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = rng.uniform(0.0, 5.0)
                complete = 0.0
                finding_count = 0.0
                high_sev = 0.0
                med_sev = 0.0

            elif scenario == "ASYMMETRIC_TRAFFIC":
                # Compound: extreme packet ratio + unusual duration + high volume
                plain, starttls, implicit = 0.0, rng.choice([1.0, 0.0]), rng.choice([0.0, 1.0])
                upgrade_adv, upgrade_req, upgrade_succ = 1.0, 1.0, 1.0
                auth_before_tls = 0.0
                tls_ver = 4.0
                cipher_str = 2.0
                pfs = 1.0
                tls_incomplete = 0.0
                cert_vis = 1.0
                cert_key_size = 2048.0
                cert_self_signed = 0.0
                cert_validity = rng.uniform(30.0, 365.0)
                cert_rsa = 1.0
                cert_ec = 0.0
                pkt_count = rng.integers(200, 2000)
                duration = rng.uniform(30.0, 300.0)
                # Extreme asymmetry: 90%+ from one side
                asym = rng.choice(["client_heavy", "server_heavy"])
                if asym == "client_heavy":
                    client_pkt = int(pkt_count * rng.uniform(0.85, 0.98))
                else:
                    client_pkt = int(pkt_count * rng.uniform(0.02, 0.10))
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = 0.0
                complete = 1.0
                finding_count = 0.0
                high_sev = 0.0
                med_sev = 0.0

            elif scenario == "MULTI_FINDING_SESSION":
                # Compound: many findings across severities + weak TLS
                plain, starttls, implicit = 0.0, 1.0, 0.0
                upgrade_adv, upgrade_req, upgrade_succ = 1.0, 1.0, 1.0
                auth_before_tls = rng.choice([0.0, 1.0])
                tls_ver = rng.choice([2.0, 3.0, 4.0])
                cipher_str = rng.choice([0.0, 1.0])
                pfs = rng.choice([0.0, 1.0])
                tls_incomplete = 0.0
                cert_vis = 1.0
                cert_key_size = rng.choice([1024.0, 2048.0])
                cert_self_signed = rng.choice([0.0, 1.0])
                cert_validity = rng.uniform(-100.0, 365.0)
                cert_rsa = 1.0
                cert_ec = 0.0
                pkt_count = rng.integers(10, 80)
                duration = rng.uniform(0.5, 10.0)
                client_pkt = int(pkt_count * rng.uniform(0.35, 0.5))
                server_pkt = pkt_count - client_pkt
                pkt_ratio = client_pkt / max(pkt_count, 1)
                reset_count = 0.0
                complete = 1.0
                finding_count = rng.integers(4, 10)
                high_sev = rng.integers(2, 5)
                med_sev = rng.integers(2, 5)

            else:
                continue

            vec = [
                smtp, imap, pop3,
                plain, starttls, implicit,
                upgrade_adv, upgrade_req, upgrade_succ,
                auth_before_tls,
                tls_ver, cipher_str, pfs, tls_incomplete,
                cert_vis, cert_key_size, cert_self_signed, cert_validity,
                cert_rsa, cert_ec,
                float(pkt_count), round(duration, 4),
                float(client_pkt), float(server_pkt),
                round(pkt_ratio, 4), float(reset_count), float(complete),
                float(finding_count), float(high_sev), float(med_sev),
            ]
            assert len(vec) == IF_FEATURE_COUNT
            samples.append(vec)
            labels.append(scenario)

    return np.array(samples), labels


