"""
Isolation Forest — Offline Training Script
============================================

Trains the Isolation Forest model on a normal baseline dataset,
evaluates on held-out data, and saves all artifacts.

Can be run as a standalone script:
    python -m analysis.anomaly_detection.train_model

Or via Django management command (if configured).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from analysis.anomaly_detection.dataset_generator import (
    generate_anomaly_scenarios,
    generate_normal_baseline,
)
from analysis.anomaly_detection.feature_schema import (
    ALL_IF_FEATURES,
    IF_BASELINE_STATS_FILENAME,
    IF_FEATURE_COUNT,
    IF_METADATA_FILENAME,
    IF_MODEL_FILENAME,
    IF_MODEL_VERSION,
    IF_SCHEMA_VERSION,
)
from analysis.anomaly_detection.preprocessing import AnomalyPreprocessor

logger = logging.getLogger(__name__)

# Default artifact directory
DEFAULT_ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"


def train_isolation_forest(
    artifact_dir: Optional[Path] = None,
    n_train: int = 2000,
    n_holdout_normal: int = 300,
    n_anomaly: int = 500,
    n_estimators: int = 200,
    contamination: float = 0.05,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Train and save the Isolation Forest model.

    Parameters
    ----------
    artifact_dir : Path
        Where to save model artifacts.
    n_train : int
        Number of normal baseline samples for training.
    n_holdout_normal : int
        Normal samples held out for validation.
    n_anomaly : int
        Anomaly scenarios for evaluation.
    n_estimators : int
        Number of trees.
    contamination : str
        IsolationForest contamination parameter.
    random_state : int
        Random seed.

    Returns
    -------
    Dict with training results and evaluation metrics.
    """
    if artifact_dir is None:
        artifact_dir = DEFAULT_ARTIFACT_DIR
    artifact_dir = Path(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("Isolation Forest Training — SecureMailScope")
    logger.info("=" * 60)

    # ── Stage 1: Generate training data ────────────────────────────
    logger.info("Generating %d normal baseline samples...", n_train + n_holdout_normal)
    X_all_normal, labels_normal = generate_normal_baseline(
        n_samples=n_train + n_holdout_normal,
        random_state=random_state,
    )

    # Split: first n_train for training, rest for holdout
    X_train = X_all_normal[:n_train]
    X_holdout_normal = X_all_normal[n_train:]

    logger.info("Training samples: %d", X_train.shape[0])
    logger.info("Holdout normal samples: %d", X_holdout_normal.shape[0])

    # ── Stage 2: Generate evaluation anomalies ─────────────────────
    logger.info("Generating %d anomaly evaluation samples...", n_anomaly)
    X_anomaly, labels_anomaly = generate_anomaly_scenarios(
        n_samples=n_anomaly,
        random_state=random_state + 57,
    )
    logger.info("Anomaly samples: %d", X_anomaly.shape[0])

    # ── Fit preprocessing on training data ONLY ────────────────────
    preprocessor = AnomalyPreprocessor()
    X_train_scaled = preprocessor.fit_transform(X_train)

    # Transform holdout and anomaly using FITTED preprocessor
    X_holdout_scaled = preprocessor.transform(X_holdout_normal)
    X_anomaly_scaled = preprocessor.transform(X_anomaly)

    # ── Train Isolation Forest ─────────────────────────────────────
    logger.info("Training IsolationForest (n_estimators=%d, contamination=%s)...",
                n_estimators, contamination)

    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples="auto",
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train_scaled)

    # ── Evaluate ──────────────────────────────────────────────────
    logger.info("Evaluating on holdout and anomaly data...")

    # Predictions (1=inlier, -1=outlier)
    pred_holdout = model.predict(X_holdout_scaled)
    pred_anomaly = model.predict(X_anomaly_scaled)

    # Scores (lower = more anomalous)
    scores_holdout = model.decision_function(X_holdout_scaled)
    scores_anomaly = model.decision_function(X_anomaly_scaled)

    # Binary labels: normal=0, anomaly=1
    y_true = np.concatenate([
        np.zeros(len(pred_holdout)),
        np.ones(len(pred_anomaly)),
    ])
    # Convert sklearn predictions: 1→0 (normal), -1→1 (anomalous)
    y_pred = np.concatenate([
        (pred_holdout == -1).astype(int),
        (pred_anomaly == -1).astype(int),
    ])
    scores_all = np.concatenate([scores_holdout, scores_anomaly])

    # Compute metrics
    try:
        roc_auc = float(roc_auc_score(y_true, -scores_all))
    except ValueError:
        roc_auc = None

    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    # Normal sample false positive rate
    normal_flagged = int(np.sum(pred_holdout == -1))
    fpr_normal = normal_flagged / len(pred_holdout)

    # Anomaly detection rate
    anomaly_detected = int(np.sum(pred_anomaly == -1))
    detection_rate = anomaly_detected / len(pred_anomaly)

    cm = confusion_matrix(y_true, y_pred).tolist()

    eval_metrics = {
        "roc_auc": round(roc_auc, 4) if roc_auc else None,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm,
        "holdout_normal_count": len(pred_holdout),
        "anomaly_count": len(pred_anomaly),
        "false_positive_rate": round(fpr_normal, 4),
        "detection_rate": round(detection_rate, 4),
        "normal_flagged_as_anomalous": normal_flagged,
        "anomaly_detected": anomaly_detected,
        "threshold": float(model.offset_),
    }

    logger.info("ROC-AUC: %s", eval_metrics["roc_auc"])
    logger.info("Precision: %s", eval_metrics["precision"])
    logger.info("Recall: %s", eval_metrics["recall"])
    logger.info("F1: %s", eval_metrics["f1_score"])
    logger.info("FPR on normal: %s", eval_metrics["false_positive_rate"])
    logger.info("Detection rate on anomalies: %s", eval_metrics["detection_rate"])

    # ── Save artifacts ─────────────────────────────────────────────
    import joblib

    # Model
    model_path = artifact_dir / IF_MODEL_FILENAME
    joblib.dump(model, model_path)
    logger.info("Model saved: %s", model_path)

    # Preprocessor
    preprocessor.save(artifact_dir)

    # Baseline stats for explanations
    baseline_stats = preprocessor.get_baseline_stats()
    stats_path = artifact_dir / IF_BASELINE_STATS_FILENAME
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(baseline_stats, f, indent=2)
    logger.info("Baseline stats saved: %s", stats_path)

    # Metadata
    metadata = {
        "model_version": IF_MODEL_VERSION,
        "schema_version": IF_SCHEMA_VERSION,
        "feature_count": IF_FEATURE_COUNT,
        "feature_names": ALL_IF_FEATURES,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "training_samples": n_train,
        "holdout_normal_samples": n_holdout_normal,
        "anomaly_eval_samples": len(pred_anomaly),
        "n_estimators": n_estimators,
        "contamination": contamination,
        "random_state": random_state,
        "evaluation_metrics": eval_metrics,
        "data_source": "synthetic_protocol_aware_baseline",
        "limitations": [
            "Model trained on synthetic normal-behavior baseline.",
            "Evaluation metrics reflect controlled synthetic scenarios, not real-world attacks.",
            "Normal but uncommon traffic may be flagged as anomalous.",
            "Malicious behavior resembling the baseline will not be detected.",
        ],
    }
    meta_path = artifact_dir / IF_METADATA_FILENAME
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Metadata saved: %s", meta_path)

    # ── Verify artifact reloadability ──────────────────────────────
    logger.info("Verifying artifact reloadability...")
    loaded_model = joblib.load(model_path)
    loaded_preprocessor = AnomalyPreprocessor.load(artifact_dir)
    test_vec = X_train_scaled[:1]
    test_pred = loaded_model.predict(test_vec)
    assert test_pred[0] in (1, -1), "Loaded model prediction failed"
    logger.info("Artifact verification passed.")

    logger.info("=" * 60)
    logger.info("Training complete.")
    logger.info("=" * 60)

    return metadata


def main() -> None:
    """CLI entry point for standalone training."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    result = train_isolation_forest()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
