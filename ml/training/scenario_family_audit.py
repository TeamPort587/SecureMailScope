"""
Scenario Family Audit
=====================

Audits each of the scenario families in the synthetic dataset to evaluate:
- Determinism and uniqueness of feature templates
- Predictability of risk_label from scenario family template
- Protocol, encryption, and finding count distributions

Output:
- ml/artifacts/scenario_family_audit.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

import numpy as np
import pandas as pd

from ml.feature_engineering.schema import ALL_FEATURES


def audit_scenario_families(
    data_path: str | Path,
) -> Dict[str, Any]:
    """Audit each scenario family for template determinism and uniqueness."""
    df = pd.read_csv(data_path)

    if "scenario_family" not in df.columns:
        raise ValueError("DataFrame must contain 'scenario_family'")

    families = df["scenario_family"].unique()
    family_audits: Dict[str, Any] = {}

    for fam in sorted(families):
        sub = df[df["scenario_family"] == fam]
        labels = sub["risk_label"].unique().tolist()

        # Protocols
        protocols = []
        if (sub["protocol_smtp"] == 1.0).any():
            protocols.append("SMTP")
        if (sub["protocol_imap"] == 1.0).any():
            protocols.append("IMAP")
        if (sub["protocol_pop3"] == 1.0).any():
            protocols.append("POP3")

        # Encryption
        enc_modes = []
        if (sub["encryption_plaintext"] == 1.0).any():
            enc_modes.append("PLAINTEXT")
        if (sub["encryption_starttls"] == 1.0).any():
            enc_modes.append("STARTTLS")
        if (sub["encryption_implicit"] == 1.0).any():
            enc_modes.append("IMPLICIT_TLS")

        # Feature variations & missingness
        active_features = {}
        missing_features = []
        constant_features = {}

        for feat in ALL_FEATURES:
            vals = sub[feat].dropna().unique()
            n_missing = sub[feat].isna().sum()

            if n_missing > 0:
                missing_features.append(feat)

            if len(vals) == 1 and n_missing == 0:
                constant_features[feat] = float(vals[0])
            elif len(vals) > 0:
                active_features[feat] = {
                    "min": float(vals.min()),
                    "max": float(vals.max()),
                    "distinct_values": [float(v) for v in sorted(vals)],
                }

        # Finding count ranges
        finding_ranges = {
            "critical_count": [int(sub["critical_count"].min()), int(sub["critical_count"].max())],
            "high_count": [int(sub["high_count"].min()), int(sub["high_count"].max())],
            "medium_count": [int(sub["medium_count"].min()), int(sub["medium_count"].max())],
            "low_count": [int(sub["low_count"].min()), int(sub["low_count"].max())],
        }

        # Determinism check: does this family map to a single label?
        is_strictly_deterministic = (len(labels) == 1)

        family_audits[fam] = {
            "risk_label": labels[0] if len(labels) == 1 else labels,
            "sample_count": len(sub),
            "is_single_label": is_strictly_deterministic,
            "protocols_used": protocols,
            "encryption_modes_used": enc_modes,
            "finding_count_ranges": finding_ranges,
            "constant_features": constant_features,
            "varying_features": list(active_features.keys()),
            "missing_features": missing_features,
            "template_determinism_risk": "HIGH" if len(constant_features) >= 12 else "MODERATE",
        }

    return {
        "total_families": len(families),
        "families": family_audits,
    }


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Audit scenario families.")
    parser.add_argument("--data", default="data/processed/combined_dataset.csv")
    parser.add_argument("--output", default="ml/artifacts/scenario_family_audit.json")
    args = parser.parse_args(argv)

    print(f"Auditing scenario families in: {args.data}")
    audit = audit_scenario_families(args.data)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2)

    print(f"Scenario family audit saved to: {out_path}")
    print(f"Audited {audit['total_families']} scenario families.")


if __name__ == "__main__":
    main()
