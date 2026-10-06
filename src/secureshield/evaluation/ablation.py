"""
secureshield.evaluation.ablation
=================================
Ablation studies to evaluate the contribution of individual components.

Tests the SecureShield system by systematically removing:
  1. Specific ML features (feature ablation)
  2. Specific correlation dimensions (correlation ablation)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import pandas as pd
from sklearn.base import clone

from secureshield.common.logging_utils import get_logger
from secureshield.detection.trainer import compute_metrics

logger = get_logger(__name__)

class AblationStudy:
    """
    Performs ablation studies to validate component contributions.
    """

    def __init__(self):
        self.results: List[Dict[str, Any]] = []

    def feature_ablation(
        self,
        base_model: Any,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_test: pd.DataFrame,
        y_test: pd.Series,
        feature_groups: Dict[str, List[str]],
    ) -> pd.DataFrame:
        """
        Evaluate performance impact when removing specific groups of features.
        e.g., removing all Volatility 'psxview' features, or 'malfind' features.

        Args:
            base_model: The unfitted model architecture.
            X_train, y_train: Training data.
            X_test, y_test: Test data.
            feature_groups: Dict mapping group_name -> list of feature names to drop.

        Returns:
            DataFrame of results showing drop in performance.
        """
        logger.info("Starting Feature Ablation Study")

        # 1. Baseline (all features)
        logger.info("Training baseline model (all features)...")
        model = clone(base_model)
        model.fit(X_train.values, y_train.values)
        y_pred = model.predict(X_test.values)
        y_prob = model.predict_proba(X_test.values)[:, 1] if hasattr(model, 'predict_proba') else None
        
        baseline_metrics = compute_metrics(y_test.values, y_pred, y_prob, "Baseline", 0.0)
        self.results.append({
            "study_type": "feature_ablation",
            "ablated_group": "None (Baseline)",
            "accuracy": baseline_metrics["accuracy"],
            "f1_macro": baseline_metrics["f1_macro"],
            "roc_auc": baseline_metrics.get("roc_auc", 0.0),
            "delta_f1": 0.0,
        })

        # 2. Ablate each group
        for group_name, features_to_drop in feature_groups.items():
            logger.info(f"Ablating feature group: {group_name}")
            
            # Find which features actually exist in the data
            cols_to_drop = [c for c in features_to_drop if c in X_train.columns]
            
            X_train_ab = X_train.drop(columns=cols_to_drop)
            X_test_ab = X_test.drop(columns=cols_to_drop)

            model_ab = clone(base_model)
            model_ab.fit(X_train_ab.values, y_train.values)
            y_pred_ab = model_ab.predict(X_test_ab.values)
            y_prob_ab = model_ab.predict_proba(X_test_ab.values)[:, 1] if hasattr(model_ab, 'predict_proba') else None
            
            metrics = compute_metrics(y_test.values, y_pred_ab, y_prob_ab, f"Ablated: {group_name}", 0.0)
            
            self.results.append({
                "study_type": "feature_ablation",
                "ablated_group": group_name,
                "accuracy": metrics["accuracy"],
                "f1_macro": metrics["f1_macro"],
                "roc_auc": metrics.get("roc_auc", 0.0),
                "delta_f1": metrics["f1_macro"] - baseline_metrics["f1_macro"],
            })

        df = pd.DataFrame([r for r in self.results if r["study_type"] == "feature_ablation"])
        return df

    def correlation_ablation(self):
        """
        Evaluate performance of incident correlation when removing specific signal dimensions
        (e.g., temporal, process, file).
        This would require a simulated dataset of multiple events, which we can approximate
        or document as future work.
        """
        logger.warning("Correlation ablation requires multi-event synthetic traces. Not fully implemented.")
        pass
