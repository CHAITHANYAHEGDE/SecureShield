"""
secureshield.preprocessing.pipeline
=====================================
Deterministic data preprocessing pipeline for CIC-MalMem-2022.

Key design choices:
- RobustScaler fitted ONLY on training partition (prevents leakage)
- Stratified 80/20 split with fixed seed
- Validation set carved from training set
- Preprocessing artifacts saved for reproducibility
- Leakage columns (Category, Filename) dropped before any split
- Duplicate removal before splitting (to avoid train/test overlap)
- Zero-variance feature removal
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit, train_test_split
from sklearn.preprocessing import RobustScaler

from secureshield.common.logging_utils import get_logger
from secureshield.data.loader import LABEL_COLUMN, LEAKAGE_COLUMNS, SELECTED_14_FEATURES

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Preprocessing pipeline
# ---------------------------------------------------------------------------

class MalMemPreprocessor:
    """
    Deterministic preprocessing pipeline for CIC-MalMem-2022.

    The pipeline:
    1. Drops leakage columns (Category, Filename)
    2. Removes duplicate rows
    3. Removes zero-variance features
    4. Stratified train/val/test split
    5. Fills NaN with zero (strategy from existing research)
    6. Fits RobustScaler on train ONLY — transforms val/test

    All artifacts (scaler, feature list, split metadata) are serialized
    for reproducibility.
    """

    def __init__(
        self,
        feature_subset: Optional[List[str]] = None,
        test_size: float = 0.20,
        val_size: float = 0.10,
        random_state: int = 42,
        fill_na_strategy: str = "zero",
        remove_zero_variance: bool = True,
        remove_duplicates: bool = True,
    ):
        self.feature_subset = feature_subset
        self.test_size = test_size
        self.val_size = val_size
        self.random_state = random_state
        self.fill_na_strategy = fill_na_strategy
        self.remove_zero_variance = remove_zero_variance
        self.remove_duplicates = remove_duplicates

        self.scaler: Optional[RobustScaler] = None
        self.selected_features_: List[str] = []
        self.preprocessing_metadata_: Dict = {}

    def fit_transform(
        self, df: pd.DataFrame
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Full preprocessing pipeline.

        Args:
            df: Raw loaded DataFrame.

        Returns:
            (X_train, X_val, X_test, y_train, y_val, y_test)
            All arrays are numpy ndarray, scaled, with no leakage.

        IMPORTANT: Scaler fitted ONLY on X_train. Val/test are transformed only.
        """
        logger.info("=== Preprocessing Pipeline Start ===")
        n_original = len(df)

        # Step 1: Drop leakage columns
        df_clean = df.drop(columns=[c for c in LEAKAGE_COLUMNS if c in df.columns], errors="ignore")
        logger.info(f"Dropped leakage columns: {[c for c in LEAKAGE_COLUMNS if c in df.columns]}")

        # Step 2: Remove duplicates BEFORE split (prevents train/test overlap)
        if self.remove_duplicates:
            n_before = len(df_clean)
            df_clean = df_clean.drop_duplicates()
            n_removed = n_before - len(df_clean)
            if n_removed > 0:
                logger.warning(
                    f"Removed {n_removed} duplicate rows before splitting. "
                    f"Remaining: {len(df_clean)} rows."
                )

        # Step 3: Separate features and labels
        X = df_clean.drop(columns=[LABEL_COLUMN])
        y = df_clean[LABEL_COLUMN].values.astype(int)

        # Step 4: Fill NaN
        if self.fill_na_strategy == "zero":
            X = X.fillna(0)
        elif self.fill_na_strategy == "median":
            X = X.fillna(X.median())
        else:
            X = X.fillna(0)

        # Step 5: Remove zero-variance columns (computed on full dataset before split)
        if self.remove_zero_variance:
            std = X.std()
            zero_var = std[std == 0].index.tolist()
            if zero_var:
                logger.warning(f"Removing zero-variance columns: {zero_var}")
                X = X.drop(columns=zero_var)

        # Step 6: Feature subset selection
        if self.feature_subset:
            available = [f for f in self.feature_subset if f in X.columns]
            missing = [f for f in self.feature_subset if f not in X.columns]
            if missing:
                logger.warning(f"Requested features not in data: {missing}")
            X = X[available]
            logger.info(f"Using feature subset: {available}")
        self.selected_features_ = list(X.columns)

        # Step 7: Stratified train+val / test split (no leakage)
        X_trainval, X_test, y_trainval, y_test = train_test_split(
            X.values, y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y,
        )

        # Step 8: Carve validation set from training set
        val_fraction_of_trainval = self.val_size / (1 - self.test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_trainval, y_trainval,
            test_size=val_fraction_of_trainval,
            random_state=self.random_state,
            stratify=y_trainval,
        )

        # Step 9: Fit scaler on TRAIN ONLY — transform val and test
        self.scaler = RobustScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)

        # Metadata for reproducibility
        self.preprocessing_metadata_ = {
            "n_original_rows": n_original,
            "n_after_dedup": len(df_clean),
            "n_duplicates_removed": n_original - len(df_clean),
            "n_features_selected": len(self.selected_features_),
            "selected_features": self.selected_features_,
            "train_size": len(X_train),
            "val_size": len(X_val),
            "test_size": len(X_test),
            "train_class_distribution": {int(k): int(v) for k, v in zip(*np.unique(y_train, return_counts=True))},
            "val_class_distribution": {int(k): int(v) for k, v in zip(*np.unique(y_val, return_counts=True))},
            "test_class_distribution": {int(k): int(v) for k, v in zip(*np.unique(y_test, return_counts=True))},
            "scaler": "RobustScaler",
            "fill_na_strategy": self.fill_na_strategy,
            "random_state": self.random_state,
            "test_fraction": self.test_size,
            "val_fraction": self.val_size,
            "leakage_note": (
                "RobustScaler fitted exclusively on training partition. "
                "Val/Test sets are transformed-only."
            ),
        }

        logger.info(
            f"Split: train={len(X_train)}, val={len(X_val)}, test={len(X_test)}"
        )
        logger.info(f"Features used: {len(self.selected_features_)}")
        logger.info(
            f"Train class dist: {self.preprocessing_metadata_['train_class_distribution']}"
        )
        logger.info("RobustScaler fitted on training set only.")
        logger.info("=== Preprocessing Pipeline Complete ===")

        return X_train_scaled, X_val_scaled, X_test_scaled, y_train, y_val, y_test

    def save(self, output_dir: str | Path) -> None:
        """Persist scaler, feature list, and metadata for reproducibility."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.scaler, output_dir / "scaler.joblib")
        logger.info(f"Scaler saved: {output_dir / 'scaler.joblib'}")

        with open(output_dir / "preprocessing_metadata.json", "w") as f:
            json.dump(self.preprocessing_metadata_, f, indent=2, default=str)
        logger.info(f"Preprocessing metadata saved: {output_dir / 'preprocessing_metadata.json'}")

    @classmethod
    def load(cls, artifacts_dir: str | Path) -> "MalMemPreprocessor":
        """Load a previously saved preprocessor for inference."""
        artifacts_dir = Path(artifacts_dir)
        preprocessor = cls()
        preprocessor.scaler = joblib.load(artifacts_dir / "scaler.joblib")
        with open(artifacts_dir / "preprocessing_metadata.json") as f:
            preprocessor.preprocessing_metadata_ = json.load(f)
        preprocessor.selected_features_ = preprocessor.preprocessing_metadata_["selected_features"]
        return preprocessor

    def transform_single(self, features: Dict) -> np.ndarray:
        """
        Transform a single feature dict for inference.

        Args:
            features: Dict mapping feature name → value.

        Returns:
            Scaled numpy array of shape (1, n_features).
        """
        if self.scaler is None:
            raise RuntimeError("Preprocessor not fitted. Call fit_transform() first.")

        row = np.array([features.get(f, 0.0) for f in self.selected_features_])
        return self.scaler.transform(row.reshape(1, -1))
