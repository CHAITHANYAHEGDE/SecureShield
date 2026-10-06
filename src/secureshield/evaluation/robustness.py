"""
secureshield.evaluation.robustness
===================================
Adversarial robustness evaluation for the malware detection model.

Tests how the model performs when features are slightly perturbed,
simulating simple evasion techniques (e.g., adding benign API calls
to dilute malicious indicators).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, accuracy_score

from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)

class RobustnessEvaluator:
    """
    Evaluates model robustness against simulated adversarial perturbations.
    """

    def __init__(self, model: Any, scaler: Any):
        self.model = model
        self.scaler = scaler
        self.results: List[Dict[str, Any]] = []

    def evaluate_noise_injection(
        self,
        X_test: pd.DataFrame,
        y_test: pd.Series,
        noise_levels: List[float] = [0.01, 0.05, 0.10, 0.20],
    ) -> pd.DataFrame:
        """
        Inject Gaussian noise into features to simulate evasive obfuscation.
        Only positive features are perturbed to mimic added API calls/sections.

        Args:
            X_test: Clean test data (pre-scaling).
            y_test: Test labels.
            noise_levels: List of standard deviations for noise (as % of feature std).

        Returns:
            DataFrame with performance degradation across noise levels.
        """
        logger.info("Starting Robustness Evaluation (Noise Injection)")

        # Baseline performance
        X_scaled = self.scaler.transform(X_test.values)
        y_pred = self.model.predict(X_scaled)
        base_f1 = f1_score(y_test.values, y_pred, average="macro")

        self.results.append({
            "perturbation_type": "noise",
            "noise_level": 0.0,
            "accuracy": accuracy_score(y_test.values, y_pred),
            "f1_macro": base_f1,
            "delta_f1": 0.0,
        })

        feature_stds = X_test.std(axis=0).values

        for level in noise_levels:
            logger.info(f"Evaluating noise level: {level}")
            
            # Create perturbed copy
            X_perturbed = X_test.copy().values
            
            # Generate positive noise proportional to feature std
            noise = np.abs(np.random.normal(0, level * feature_stds, X_perturbed.shape))
            
            # Add noise (simulating adding more handles, more sections, etc.)
            X_perturbed = X_perturbed + noise

            # Transform and predict
            X_perturbed_scaled = self.scaler.transform(X_perturbed)
            y_pred_perturbed = self.model.predict(X_perturbed_scaled)
            
            f1 = f1_score(y_test.values, y_pred_perturbed, average="macro")
            acc = accuracy_score(y_test.values, y_pred_perturbed)

            self.results.append({
                "perturbation_type": "noise",
                "noise_level": level,
                "accuracy": acc,
                "f1_macro": f1,
                "delta_f1": f1 - base_f1,
            })

        df = pd.DataFrame(self.results)
        return df
