"""
Feature Interaction & Label Purity Analysis
===========================================

Analyzes pairwise feature combinations to detect extreme label purity (>0.98).
Distinguishes legitimate domain determinism (e.g., critical_count >= 1 -> CRITICAL)
from suspicious synthetic shortcuts.

CLI Usage::

    python -m ml.training.interaction_analysis \\
        --input data/processed/train.csv \\
        --threshold 0.98 \\
        --min-samples 15 \\
        --output-json ml/artifacts/feature_interaction_report.json \\
        --output-txt ml/artifacts/feature_interaction_report.txt
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from ml.feature_engineering.schema import ALL_FEATURES, RISK_LABELS


LEGITIMATE_TRIGGERS = [
    ("critical_count", "HIGH_OR_ABOVE"),  # critical_count >= 1 -> CRITICAL
    ("encryption_plaintext", "CRITICAL"), # plaintext -> CRITICAL
    ("auth_before_tls", "CRITICAL"),      # early auth -> CRITICAL
]


def is_legitimate_domain_rule(f1: str, f2: str, dominant_class: str) -> Tuple[bool, str]:
    """Check if high purity for (f1, f2) is justified by canonical security domain rules."""
    # Plaintext sessions are always CRITICAL by definition
    if ("encryption_plaintext" in (f1, f2)) and dominant_class == "CRITICAL":
        return True, "Plaintext email transmission is fundamentally unencrypted (CRITICAL rule 1.3)"

    # Early authentication before TLS is always CRITICAL
    if ("auth_before_tls" in (f1, f2)) and dominant_class == "CRITICAL":
        return True, "Cleartext credential transmission prior to TLS handshake is inherently CRITICAL (rule 1.2)"

    # critical_count >= 1 is always CRITICAL
    if ("critical_count" in (f1, f2)) and dominant_class == "CRITICAL":
        return True, "Active rule engine critical finding mandates CRITICAL (rule 1.1)"

    # Compounding major failures (failed upgrade + weak cipher / deprecated TLS)
    if "tls_upgrade_failed" in (f1, f2) and ("weak_cipher" in (f1, f2) or "deprecated_tls" in (f1, f2)):
        if dominant_class in ("HIGH", "CRITICAL"):
            return True, "Compounding upgrade failure with weak crypto constitutes compounding failure (rule 1.4)"

    # Deprecated TLS + weak cipher compounding
    if "deprecated_tls" in (f1, f2) and "weak_cipher" in (f1, f2) and dominant_class in ("HIGH", "CRITICAL"):
        return True, "Combination of obsolete protocol and weak cipher represents severe flaw (rule 1.4 / 2.2)"

    # Self-signed + missing PFS
    if "self_signed" in (f1, f2) and "pfs_missing" in (f1, f2) and dominant_class in ("MEDIUM", "HIGH"):
        return True, "Compounding moderate flaws (self-signed + no PFS) escalate risk (rule 2.3)"

    return False, "Synthetic feature pairing with unexpectedly high purity; audit for shortcut"


def analyze_feature_interactions(
    df: pd.DataFrame,
    purity_threshold: float = 0.98,
    min_samples: int = 15,
) -> Dict[str, Any]:
    """Analyze all pairwise feature combinations for extreme label purity."""
    if "risk_label" not in df.columns:
        raise ValueError("Dataset missing 'risk_label' column.")

    total_rows = len(df)
    features = [f for f in ALL_FEATURES if f in df.columns]

    flagged_interactions: List[Dict[str, Any]] = []
    analyzed_pairs_count = 0

    for f1, f2 in itertools.combinations(features, 2):
        # We analyze conditions where both features are active / present
        # For numeric counts, check > 0; for binary, check == 1.0
        s1 = df[f1]
        s2 = df[f2]

        cond1 = (s1 > 0) if "count" in f1 else (s1 == 1.0)
        cond2 = (s2 > 0) if "count" in f2 else (s2 == 1.0)

        joint_subset = df[cond1 & cond2]
        count = len(joint_subset)

        if count < min_samples:
            continue

        analyzed_pairs_count += 1
        class_counts = joint_subset["risk_label"].value_counts()
        dominant_class = str(class_counts.index[0])
        dominant_count = int(class_counts.iloc[0])
        purity = dominant_count / count

        if purity >= purity_threshold:
            is_legit, rationale = is_legitimate_domain_rule(f1, f2, dominant_class)
            flagged_interactions.append({
                "feature_1": f1,
                "feature_2": f2,
                "sample_count": count,
                "purity": round(float(purity), 4),
                "dominant_class": dominant_class,
                "class_breakdown": {str(k): int(v) for k, v in class_counts.items()},
                "classification": "LEGITIMATE_DOMAIN_RULE" if is_legit else "SUSPICIOUS_SYNTHETIC_SHORTCUT",
                "rationale": rationale,
            })

    # Sort flagged interactions by purity desc, sample_count desc
    flagged_interactions.sort(key=lambda x: (x["purity"], x["sample_count"]), reverse=True)

    legit_count = sum(1 for item in flagged_interactions if item["classification"] == "LEGITIMATE_DOMAIN_RULE")
    shortcut_count = sum(1 for item in flagged_interactions if item["classification"] == "SUSPICIOUS_SYNTHETIC_SHORTCUT")

    return {
        "dataset_total_rows": total_rows,
        "analyzed_feature_pairs_above_min_samples": analyzed_pairs_count,
        "purity_threshold": purity_threshold,
        "min_samples": min_samples,
        "total_flagged_interactions": len(flagged_interactions),
        "legitimate_domain_rules_count": legit_count,
        "suspicious_shortcuts_count": shortcut_count,
        "flagged_interactions": flagged_interactions,
    }


def format_text_report(report: Dict[str, Any]) -> str:
    """Format interaction report into readable text."""
    lines = [
        "==================================================================",
        "SECUREMAILSCOPE PAIRWISE FEATURE INTERACTION & PURITY REPORT",
        "==================================================================",
        f"Total Samples Analyzed:       {report['dataset_total_rows']}",
        f"Pairs Above Min Samples ({report['min_samples']}): {report['analyzed_feature_pairs_above_min_samples']}",
        f"Purity Threshold:             {report['purity_threshold']:.1%}",
        f"Total Flagged Interactions:   {report['total_flagged_interactions']}",
        f"  - Legitimate Domain Rules:  {report['legitimate_domain_rules_count']}",
        f"  - Suspicious Shortcuts:     {report['suspicious_shortcuts_count']}",
        "",
        "--- DETAILED FLAGGED INTERACTIONS ---",
    ]

    for idx, item in enumerate(report["flagged_interactions"], 1):
        lines.append(
            f"{idx}. [{item['classification']}] {item['feature_1']} + {item['feature_2']}"
        )
        lines.append(f"   Dominant Class: {item['dominant_class']} (Purity: {item['purity']:.2%}, N={item['sample_count']})")
        lines.append(f"   Breakdown: {item['class_breakdown']}")
        lines.append(f"   Rationale: {item['rationale']}")
        lines.append("")

    return "\n".join(lines)


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Analyze pairwise feature interaction label purity.")
    parser.add_argument("--input", default="data/processed/train.csv", help="Path to input dataset.")
    parser.add_argument("--threshold", type=float, default=0.98, help="Purity threshold (0-1).")
    parser.add_argument("--min-samples", type=int, default=15, help="Minimum joint samples to analyze.")
    parser.add_argument("--output-json", default="ml/artifacts/feature_interaction_report.json", help="Output JSON path.")
    parser.add_argument("--output-txt", default="ml/artifacts/feature_interaction_report.txt", help="Output text path.")
    args = parser.parse_args(argv)

    print(f"Analyzing feature interactions on {args.input}...")
    df = pd.read_csv(args.input)
    report = analyze_feature_interactions(df, purity_threshold=args.threshold, min_samples=args.min_samples)

    out_json = Path(args.output_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"  Saved JSON report to: {out_json}")

    out_txt = Path(args.output_txt)
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(format_text_report(report))
    print(f"  Saved Text report to: {out_txt}")

    print(f"  Flagged interactions: {report['total_flagged_interactions']} "
          f"(Legitimate: {report['legitimate_domain_rules_count']}, "
          f"Suspicious Shortcuts: {report['suspicious_shortcuts_count']})")


if __name__ == "__main__":
    main()
