"""
Tests for ml.training.dataset_builder — dataset construction.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from ml.training.dataset_builder import (
    build_dataset,
    load_analysis_files,
    load_labels,
)
from ml.feature_engineering.schema import ALL_FEATURES


# ── Fixtures ───────────────────────────────────────────────────────

SAMPLE_ANALYSIS = {
    "analysis_version": "1.0.0",
    "file": {"analysis_id": "analysis-001"},
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
        },
        {
            "session_id": "imap-001",
            "protocol": "IMAP",
            "security": {
                "encryption_mode": "PLAINTEXT",
                "upgrade_advertised": "NO",
                "upgrade_requested": "NO",
                "upgrade_succeeded": "NO",
                "authentication_before_tls": "YES",
            },
            "tls": None,
            "certificate": None,
        },
    ],
    "findings": [
        {
            "finding_id": "finding-001",
            "session_id": "imap-001",
            "finding_type": "PLAINTEXT",
            "severity": "CRITICAL",
        }
    ],
}


@pytest.fixture
def tmp_analysis_dir(tmp_path: Path) -> Path:
    """Create a temp dir with a sample analysis JSON."""
    d = tmp_path / "curated"
    d.mkdir()
    with open(d / "analysis-001.json", "w") as f:
        json.dump(SAMPLE_ANALYSIS, f)
    return d


@pytest.fixture
def tmp_labels_csv(tmp_path: Path) -> Path:
    """Create a temp labels CSV."""
    csv_path = tmp_path / "labels.csv"
    csv_path.write_text(
        "analysis_id,session_id,risk_label\n"
        "analysis-001,smtp-001,LOW\n"
        "analysis-001,imap-001,CRITICAL\n"
    )
    return csv_path


# ── Load analysis files ───────────────────────────────────────────

class TestLoadAnalysisFiles:
    def test_loads_json_files(self, tmp_analysis_dir: Path) -> None:
        analyses = load_analysis_files(tmp_analysis_dir)
        assert len(analyses) == 1

    def test_analysis_has_id(self, tmp_analysis_dir: Path) -> None:
        analyses = load_analysis_files(tmp_analysis_dir)
        assert analyses[0]["_analysis_id"] == "analysis-001"

    def test_missing_dir_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_analysis_files("/nonexistent/dir")


# ── Load labels ───────────────────────────────────────────────────

class TestLoadLabels:
    def test_loads_csv(self, tmp_labels_csv: Path) -> None:
        df = load_labels(tmp_labels_csv)
        assert len(df) == 2

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_labels("/nonexistent/labels.csv")

    def test_missing_columns_raises(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "bad.csv"
        csv_path.write_text("col_a,col_b\n1,2\n")
        with pytest.raises(ValueError, match="missing required columns"):
            load_labels(csv_path)

    def test_invalid_label_raises(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "bad_labels.csv"
        csv_path.write_text(
            "analysis_id,session_id,risk_label\n"
            "a-001,s-001,SUPER_BAD\n"
        )
        with pytest.raises(ValueError, match="Invalid risk labels"):
            load_labels(csv_path)


# ── Build dataset ─────────────────────────────────────────────────

class TestBuildDataset:
    def test_multiple_sessions(self, tmp_analysis_dir: Path) -> None:
        analyses = load_analysis_files(tmp_analysis_dir)
        df = build_dataset(analyses)
        assert len(df) == 2  # 2 sessions

    def test_has_all_features(self, tmp_analysis_dir: Path) -> None:
        analyses = load_analysis_files(tmp_analysis_dir)
        df = build_dataset(analyses)
        for feat in ALL_FEATURES:
            assert feat in df.columns

    def test_correct_label_joining(
        self, tmp_analysis_dir: Path, tmp_labels_csv: Path
    ) -> None:
        analyses = load_analysis_files(tmp_analysis_dir)
        labels_df = load_labels(tmp_labels_csv)
        df = build_dataset(analyses, labels_df)
        assert "risk_label" in df.columns
        assert len(df) == 2

    def test_missing_labels_inner_join(
        self, tmp_analysis_dir: Path, tmp_path: Path
    ) -> None:
        """Sessions without matching labels are excluded (inner join)."""
        csv_path = tmp_path / "partial.csv"
        csv_path.write_text(
            "analysis_id,session_id,risk_label\n"
            "analysis-001,smtp-001,LOW\n"
        )
        analyses = load_analysis_files(tmp_analysis_dir)
        labels_df = load_labels(csv_path)
        df = build_dataset(analyses, labels_df)
        assert len(df) == 1  # Only smtp-001 has a label

    def test_no_labels_returns_unlabeled(
        self, tmp_analysis_dir: Path
    ) -> None:
        analyses = load_analysis_files(tmp_analysis_dir)
        df = build_dataset(analyses)
        assert "risk_label" not in df.columns
