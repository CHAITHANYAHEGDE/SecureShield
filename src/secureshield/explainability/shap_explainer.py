"""
secureshield.explainability.shap_explainer
==========================================
SHAP-based model explainability for malware detection.

IMPORTANT EPISTEMOLOGICAL NOTE:
  SHAP provides model explanation — it describes which features most influenced
  a specific prediction. It does NOT prove causality. Feature importance is
  correlation-based and model-specific. Explanations should be treated as
  evidence for investigation, not as ground truth.

Outputs:
  - Global feature importance (mean |SHAP|)
  - Local explanations per instance
  - Structured JSON for downstream correlation engine
  - Figures for publication
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False

from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# SHAP Explainer
# ---------------------------------------------------------------------------

class MalwareExplainer:
    """
    Computes SHAP explanations for the trained malware detector.

    Uses TreeExplainer for tree-based models (fast exact computation).
    Falls back to KernelExplainer for other model types (slow, approximate).
    """

    def __init__(
        self,
        model: Any,
        feature_names: List[str],
        max_samples: int = 500,
    ):
        self.model = model
        self.feature_names = feature_names
        self.max_samples = max_samples
        self._explainer = None
        self._shap_values = None
        self._shap_expected_value = None

    def _build_explainer(self, X_background: np.ndarray) -> None:
        """Initialize SHAP explainer based on model type."""
        if not HAS_SHAP:
            raise ImportError("shap package not installed.")

        model_type = type(self.model).__name__
        tree_based = any(
            t in model_type for t in
            ["Forest", "Tree", "Boost", "LGBM", "XGB", "CatBoost", "Extra"]
        )

        if tree_based:
            logger.info(f"Using TreeExplainer for {model_type}")
            self._explainer = shap.TreeExplainer(self.model)
        else:
            logger.info(f"Using KernelExplainer for {model_type} (slow — using 100 background samples)")
            background = shap.sample(X_background, min(100, len(X_background)))
            self._explainer = shap.KernelExplainer(
                self.model.predict_proba if hasattr(self.model, "predict_proba")
                else self.model.predict,
                background,
            )

    def compute_shap_values(
        self,
        X: np.ndarray,
        use_samples: Optional[int] = None,
    ) -> np.ndarray:
        """
        Compute SHAP values for the given instances.

        Args:
            X: Feature matrix.
            use_samples: If given, subsample X to this many instances.

        Returns:
            SHAP values array of shape (n_samples, n_features).
        """
        if not HAS_SHAP:
            raise ImportError("shap package not installed.")

        if self._explainer is None:
            self._build_explainer(X)

        n = use_samples or self.max_samples
        X_subset = X[:n]

        logger.info(f"Computing SHAP values for {len(X_subset)} instances...")
        raw = self._explainer.shap_values(X_subset)

        # Handle list output (binary classification — take class 1)
        if isinstance(raw, list):
            if len(raw) == 2:
                self._shap_values = raw[1]  # malware class
            else:
                self._shap_values = raw[0]
        else:
            if isinstance(raw, np.ndarray) and raw.ndim == 3 and raw.shape[2] == 2:
                self._shap_values = raw[:, :, 1]
            else:
                self._shap_values = raw

        if hasattr(self._explainer, "expected_value"):
            ev = self._explainer.expected_value
            if isinstance(ev, (list, np.ndarray)) and len(ev) > 1:
                self._shap_expected_value = float(ev[1])
            elif isinstance(ev, (list, np.ndarray)) and len(ev) == 1:
                self._shap_expected_value = float(ev[0])
            else:
                self._shap_expected_value = float(ev)

        logger.info(f"SHAP values computed. Shape: {self._shap_values.shape}")
        return self._shap_values

    def global_feature_importance(self, top_k: int = 20) -> pd.DataFrame:
        """
        Compute global feature importance as mean |SHAP| value.

        Args:
            top_k: Return top-k features.

        Returns:
            DataFrame with columns ['feature', 'mean_abs_shap', 'rank'].
        """
        if self._shap_values is None:
            raise RuntimeError("Call compute_shap_values() first.")

        mean_abs = np.abs(self._shap_values).mean(axis=0)
        importance_df = pd.DataFrame({
            "feature": self.feature_names,
            "mean_abs_shap": mean_abs,
        }).sort_values("mean_abs_shap", ascending=False).reset_index(drop=True)
        importance_df["rank"] = importance_df.index + 1

        return importance_df.head(top_k)

    def local_explanation(
        self,
        instance_index: int,
        prediction: int,
        confidence: float,
        top_k: int = 10,
    ) -> Dict[str, Any]:
        """
        Generate a structured local explanation for a single prediction.

        This output feeds directly into the SecureShield correlation engine.

        Args:
            instance_index: Index into the SHAP-computed subset.
            prediction: Model prediction (0=Benign, 1=Malware).
            confidence: Probability score for the predicted class.
            top_k: Number of top contributing features to include.

        Returns:
            Structured explanation dict.

        NOTE: SHAP explains the model's decision for this instance.
              It is NOT causal ground truth — it is model-specific evidence.
        """
        if self._shap_values is None:
            raise RuntimeError("Call compute_shap_values() first.")

        shap_row = self._shap_values[instance_index]
        ranked_idx = np.argsort(np.abs(shap_row))[::-1]

        top_features = []
        for i in ranked_idx[:top_k]:
            top_features.append({
                "feature": self.feature_names[i],
                "shap_contribution": float(shap_row[i]),
                "abs_contribution": float(abs(shap_row[i])),
                "direction": "malicious" if shap_row[i] > 0 else "benign",
            })

        return {
            "prediction": "malicious" if prediction == 1 else "benign",
            "confidence": round(confidence, 4),
            "expected_value": self._shap_expected_value,
            "top_features": top_features,
            "explanation_type": "SHAP_TreeExplainer",
            "epistemological_note": (
                "SHAP explains the model's prediction for this instance. "
                "It describes feature contribution to the model output, not causal relationships. "
                "Treat as evidence for investigation, not ground truth."
            ),
        }

    def batch_explanations(
        self,
        X: np.ndarray,
        y_pred: np.ndarray,
        y_prob: np.ndarray,
        top_k: int = 10,
    ) -> List[Dict[str, Any]]:
        """Generate explanations for multiple instances."""
        if self._shap_values is None:
            self.compute_shap_values(X)

        n = len(self._shap_values)
        explanations = []
        for i in range(n):
            explanations.append(
                self.local_explanation(
                    i,
                    prediction=int(y_pred[i]) if i < len(y_pred) else 0,
                    confidence=float(y_prob[i]) if i < len(y_prob) else 0.5,
                    top_k=top_k,
                )
            )
        return explanations

    def save(self, output_dir: str | Path) -> None:
        """Save global importance table."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        importance_df = self.global_feature_importance()
        importance_df.to_csv(output_dir / "shap_global_importance.csv", index=False)
        logger.info(f"SHAP global importance saved: {output_dir / 'shap_global_importance.csv'}")

        if self._shap_values is not None:
            np.save(output_dir / "shap_values.npy", self._shap_values)
            logger.info(f"SHAP values array saved: {output_dir / 'shap_values.npy'}")
