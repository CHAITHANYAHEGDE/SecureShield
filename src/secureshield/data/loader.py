"""
secureshield.data.loader
========================
Loads CIC-MalMem-2022 dataset with full provenance tracking and quality reporting.
Performs no transformations — raw loading and inspection only.

Dataset: CIC-MalMem-2022
Source: https://www.unb.ca/cic/datasets/malmem-2022.html
Features: 53 Volatility-extracted volatile memory process attributes
Label: Class (0=Benign, 1=Malware)
"""

from __future__ import annotations

import json
import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import numpy as np
import pandas as pd

from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# All 52 raw Volatility features in canonical order (excluding label columns)
# ---------------------------------------------------------------------------
RAW_52_FEATURES = [
    "pslist.nproc", "pslist.nppid", "pslist.avg_threads", "pslist.avg_handlers",
    "dlllist.ndlls", "dlllist.avg_dlls_per_proc",
    "handles.nhandles", "handles.avg_handles_per_proc",
    "handles.nfile", "handles.nevent", "handles.ndesktop",
    "handles.nkey", "handles.nthread", "handles.ndirectory",
    "handles.nsemaphore", "handles.ntimer", "handles.nsection", "handles.nmutant",
    "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
    "ldrmodules.not_in_load_avg", "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg",
    "malfind.ninjections", "malfind.commitCharge", "malfind.protection",
    "malfind.uniqueInjections",
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool", "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list", "psxview.not_in_csrss_handles",
    "psxview.not_in_session", "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg", "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg", "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg", "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",
    "modules.nmodules",
    "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.fs_drivers",
    "svcscan.process_services", "svcscan.shared_process_services", "svcscan.nactive",
    "callbacks.ncallbacks", "callbacks.nanonymous", "callbacks.ngeneric",
]

# Research-validated 14-feature subset (from existing pipeline)
SELECTED_14_FEATURES = [
    "handles.ndesktop", "svcscan.nservices", "pslist.nppid", "malfind.commitCharge",
    "handles.nsemaphore", "svcscan.nactive", "ldrmodules.not_in_load",
    "ldrmodules.not_in_load_avg", "pslist.avg_handlers", "handles.nsection",
    "dlllist.avg_dlls_per_proc", "handles.nmutant", "handles.nkey",
    "malfind.ninjections",
]

LABEL_COLUMN = "Class"
LEAKAGE_COLUMNS = ["Category", "Filename"]


# ---------------------------------------------------------------------------
# Dataset loading and quality reporting
# ---------------------------------------------------------------------------

def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 checksum for dataset provenance tracking."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def load_raw_dataset(path: str | Path) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Load the raw CIC-MalMem-2022 CSV and return a quality report.

    Args:
        path: Path to the raw CSV file.

    Returns:
        (DataFrame, quality_report dict)

    Raises:
        FileNotFoundError: If dataset file does not exist.
        ValueError: If expected label column is missing.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at: {path.resolve()}\n"
            "Download from: https://www.unb.ca/cic/datasets/malmem-2022.html\n"
            "Set path via: SECURESHIELD_DATASET env var or --dataset-path CLI flag."
        )

    logger.info(f"Loading dataset: {path}")
    df = pd.read_csv(path)

    # Validate label column
    if LABEL_COLUMN not in df.columns:
        raise ValueError(
            f"Label column '{LABEL_COLUMN}' not found. "
            f"Available columns: {list(df.columns)}"
        )

    sha256 = compute_file_sha256(path)
    logger.info(f"Dataset SHA-256: {sha256}")

    # ── Quality Report ──────────────────────────────────────────────────────
    class_counts = df[LABEL_COLUMN].value_counts().to_dict()
    n_total = len(df)
    n_duplicates = int(df.duplicated().sum())
    n_missing = int(df.isnull().sum().sum())

    # Per-column missing
    col_missing = df.isnull().sum()
    cols_with_missing = col_missing[col_missing > 0].to_dict()

    # Zero-variance columns (informative for feature selection)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    zero_var_cols = [c for c in numeric_cols if df[c].std() == 0]

    # Leakage column detection
    leakage_present = [c for c in LEAKAGE_COLUMNS if c in df.columns]

    # Cross-feature correlation check (detect perfect correlation — potential leakage)
    feature_cols = [c for c in df.columns if c not in [LABEL_COLUMN] + LEAKAGE_COLUMNS]
    numeric_feature_cols = df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()

    quality_report: Dict[str, Any] = {
        "dataset_path": str(path.resolve()),
        "sha256": sha256,
        "n_rows": n_total,
        "n_columns": len(df.columns),
        "class_distribution": class_counts,
        "class_balance_pct": {
            k: round(v / n_total * 100, 2) for k, v in class_counts.items()
        },
        "n_missing_values": n_missing,
        "columns_with_missing": cols_with_missing,
        "n_duplicate_rows": n_duplicates,
        "duplicate_fraction": round(n_duplicates / n_total, 6) if n_total else 0,
        "zero_variance_columns": zero_var_cols,
        "leakage_columns_detected": leakage_present,
        "n_numeric_features": len(numeric_feature_cols),
        "feature_names": numeric_feature_cols,
    }

    # Log summary
    logger.info(f"Rows: {n_total}, Columns: {len(df.columns)}")
    logger.info(f"Class distribution: {class_counts}")
    logger.info(f"Missing values: {n_missing}")
    logger.info(f"Duplicate rows: {n_duplicates} ({quality_report['duplicate_fraction']:.4%})")
    logger.info(f"Zero-variance columns: {zero_var_cols}")
    logger.info(f"Leakage columns present: {leakage_present}")

    if n_duplicates > 0:
        logger.warning(
            f"REPRODUCIBILITY WARNING: {n_duplicates} duplicate rows detected. "
            "These may artificially inflate test-set performance if not removed before splitting."
        )

    return df, quality_report


def save_quality_report(report: Dict[str, Any], output_path: str | Path) -> None:
    """Save the quality report as JSON for auditing."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info(f"Quality report saved: {output_path}")
