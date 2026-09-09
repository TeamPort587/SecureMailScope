"""
Tests for ml.inference.predictor — inference and prediction.

Uses a small synthetic model trained in a fixture to test the full
prediction pipeline end-to-end.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pytest

from ml.feature_engineering.encoder import build_pipeline, prepare_feature_matrix
from ml.feature_engineering.schema import ALL_FEATURES, FEATURE_COUNT, SCHEMA_VERSION
from ml.inference.predictor import (
    ModelLoadError,
    RiskPredictor,
    SchemaVersionMismatch,
    FeatureCountMismatch,
    aggregate_pcap_risk,
)


# ── Fixtures ───────────────────────────────────────────────────────

def _make_feature_vec(**overrides: float) -> dict:
    vec = {f: 0.0 for f in ALL_FEATURES}
    vec.update(overrides)
    return vec


def _train_and_save_tiny_model(output_dir: Path) -> None:
    """Train a tiny model on synthetic data and save it."""
    # 4 rows, one per class
    rows = [
        _make_feature_vec(encryption_starttls=1, protocol_smtp=1),
        _make_feature_vec(encryption_plaintext=1, protocol_imap=1, auth_before_tls=1, critical_count=2),
        _make_feature_vec(encryption_starttls=1, protocol_pop3=1, deprecated_tls=1, high_count=1),
        _make_feature_vec(encryption_implicit=1, protocol_smtp=1, weak_cipher=1, medium_count=1),
    ]
    labels = ["LOW", "CRITICAL", "HIGH", "MEDIUM"]

    mat = prepare_feature_matrix(rows)
    pipe = build_pipeline(n_estimators=10, random_state=42)
    pipe.fit(mat, labels)

    # Save model
    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, output_dir / "risk_model.joblib")

    # Save metadata
    metadata = {
        "model_version": "rf-v1",
        "schema_version": SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "feature_names": ALL_FEATURES,
        "training_timestamp": "2026-01-01T00:00:00Z",
        "label_classes": ["CRITICAL", "HIGH", "LOW", "MEDIUM"],
        "training_rows": 4,
        "test_rows": 0,
        "random_state": 42,
    }
    with open(output_dir / "model_metadata.json", "w") as f:
        json.dump(metadata, f)


@pytest.fixture
def model_dir(tmp_path: Path) -> Path:
    d = tmp_path / "artifacts"
    _train_and_save_tiny_model(d)
    return d


@pytest.fixture
def predictor(model_dir: Path) -> RiskPredictor:
    return RiskPredictor(model_dir)


SAMPLE_ANALYSIS: dict = {
    "analysis_version": "1.0.0",
    "sessions": [
        {
            "session_id": "smtp-001",
            "protocol": "SMTP",
            "security": {
                "encryption_mode": "STARTTLS",
                "upgrade_advertised": "YES",
                "upgrade_requested": "YES",
                "upgrade_succeeded": "YES",
                "authentication_before_tls": "NO",
            },
            "tls": {
                "version": "TLS 1.2",
                "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "pfs": "YES",
            },
            "certificate": {
                "subject": "CN=mail.example.com",
                "issuer": "Example CA",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "key_type": "RSA",
                "key_size": 2048,
                "self_signed": False,
            },
        }
    ],
    "findings": [],
}


# ── Model loading ─────────────────────────────────────────────────

class TestModelLoading:
    def test_loads_successfully(self, model_dir: Path) -> None:
        p = RiskPredictor(model_dir)
        assert p.pipeline is not None

    def test_metadata_loaded(self, predictor: RiskPredictor) -> None:
        assert predictor.metadata["model_version"] == "rf-v1"
        assert predictor.metadata["schema_version"] == SCHEMA_VERSION


# ── Prediction output ─────────────────────────────────────────────

class TestPrediction:
    def test_valid_prediction(self, predictor: RiskPredictor) -> None:
        session = SAMPLE_ANALYSIS["sessions"][0]
        result = predictor.predict_session(session, [])
        assert "risk" in result
        assert result["risk"]["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_confidence_present(self, predictor: RiskPredictor) -> None:
        session = SAMPLE_ANALYSIS["sessions"][0]
        result = predictor.predict_session(session, [])
        assert "confidence" in result["risk"]
        assert 0 <= result["risk"]["confidence"] <= 1

    def test_feature_order_preserved(self, predictor: RiskPredictor) -> None:
        session = SAMPLE_ANALYSIS["sessions"][0]
        result = predictor.predict_session(session, [])
        assert "features_used" in result
        assert set(result["features_used"].keys()) == set(ALL_FEATURES)

    def test_session_id_in_output(self, predictor: RiskPredictor) -> None:
        session = SAMPLE_ANALYSIS["sessions"][0]
        result = predictor.predict_session(session, [])
        assert result["session_id"] == "smtp-001"

    def test_model_version_in_output(self, predictor: RiskPredictor) -> None:
        session = SAMPLE_ANALYSIS["sessions"][0]
        result = predictor.predict_session(session, [])
        assert result["risk"]["model_version"] == "rf-v1"

    def test_output_is_json_serializable(self, predictor: RiskPredictor) -> None:
        session = SAMPLE_ANALYSIS["sessions"][0]
        result = predictor.predict_session(session, [])
        # Must not raise
        json.dumps(result)


# ── Batch prediction ──────────────────────────────────────────────

class TestBatchPrediction:
    def test_predict_analysis(self, predictor: RiskPredictor) -> None:
        result = predictor.predict_analysis(SAMPLE_ANALYSIS)
        assert "session_predictions" in result
        assert len(result["session_predictions"]) == 1

    def test_batch_output_structure(self, predictor: RiskPredictor) -> None:
        result = predictor.predict_analysis(SAMPLE_ANALYSIS)
        assert result["model_version"] == "rf-v1"
        assert result["feature_schema_version"] == SCHEMA_VERSION

    def test_batch_json_serializable(self, predictor: RiskPredictor) -> None:
        result = predictor.predict_analysis(SAMPLE_ANALYSIS)
        json.dumps(result)  # Must not raise


# ── PCAP aggregation ──────────────────────────────────────────────

class TestPCAPAggregation:
    def test_critical_overrides_all(self) -> None:
        preds = [
            {"risk": {"level": "LOW", "confidence": 0.9}},
            {"risk": {"level": "CRITICAL", "confidence": 0.8}},
        ]
        result = aggregate_pcap_risk(preds)
        assert result["overall_risk_level"] == "CRITICAL"

    def test_high_when_no_critical(self) -> None:
        preds = [
            {"risk": {"level": "LOW", "confidence": 0.9}},
            {"risk": {"level": "HIGH", "confidence": 0.7}},
        ]
        result = aggregate_pcap_risk(preds)
        assert result["overall_risk_level"] == "HIGH"

    def test_empty_predictions(self) -> None:
        result = aggregate_pcap_risk([])
        assert result["overall_risk_level"] == "LOW"

    def test_confidence_from_highest_level(self) -> None:
        preds = [
            {"risk": {"level": "HIGH", "confidence": 0.6}},
            {"risk": {"level": "HIGH", "confidence": 0.9}},
            {"risk": {"level": "LOW", "confidence": 0.99}},
        ]
        result = aggregate_pcap_risk(preds)
        assert result["overall_risk_level"] == "HIGH"
        assert result["overall_confidence"] == 0.9
