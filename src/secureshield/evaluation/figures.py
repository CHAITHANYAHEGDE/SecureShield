"""
secureshield.evaluation.figures
================================
Visualization generation for the SecureShield research paper.

Generates high-quality, publication-ready figures:
  - ROC / PR Curves
  - SHAP Summary Plots
  - Confusion Matrices
  - Ablation / Robustness degradation charts
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    PrecisionRecallDisplay,
    RocCurveDisplay,
    confusion_matrix,
    roc_curve,
    auc,
)

from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)

# Standard publication styling
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams.update({
    "font.size": 12,
    "axes.labelsize": 14,
    "axes.titlesize": 16,
    "legend.fontsize": 12,
    "xtick.labelsize": 12,
    "ytick.labelsize": 12,
    "figure.dpi": 300,
    "savefig.bbox": "tight",
})


class FigureGenerator:
    """
    Generates paper-ready figures and saves them to the specified directory.
    """

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def plot_roc_curve(
        self,
        y_true: np.ndarray,
        y_probs: Dict[str, np.ndarray],
        filename: str = "roc_curve.pdf",
    ) -> None:
        """Plot ROC curves for multiple models."""
        logger.info(f"Generating ROC curve: {filename}")
        fig, ax = plt.subplots(figsize=(8, 6))

        for model_name, y_prob in y_probs.items():
            fpr, tpr, _ = roc_curve(y_true, y_prob)
            roc_auc = auc(fpr, tpr)
            ax.plot(fpr, tpr, lw=2, label=f"{model_name} (AUC = {roc_auc:.3f})")

        ax.plot([0, 1], [0, 1], color="gray", lw=1.5, linestyle="--")
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.set_xlabel("False Positive Rate")
        ax.set_ylabel("True Positive Rate")
        ax.set_title("Receiver Operating Characteristic")
        ax.legend(loc="lower right")

        plt.savefig(self.output_dir / filename)
        plt.close()

    def plot_confusion_matrix(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        model_name: str,
        filename: str = "confusion_matrix.pdf",
    ) -> None:
        """Plot a styled confusion matrix."""
        logger.info(f"Generating Confusion Matrix: {filename}")
        cm = confusion_matrix(y_true, y_pred)
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Benign", "Malware"])
        
        fig, ax = plt.subplots(figsize=(6, 5))
        disp.plot(cmap=plt.cm.Blues, ax=ax, values_format="d")
        ax.set_title(f"Confusion Matrix ({model_name})")
        ax.grid(False)

        plt.savefig(self.output_dir / filename)
        plt.close()

    def plot_shap_summary(
        self,
        shap_df: pd.DataFrame,
        filename: str = "shap_importance.pdf",
    ) -> None:
        """Plot SHAP global feature importance (bar chart)."""
        logger.info(f"Generating SHAP Summary: {filename}")
        fig, ax = plt.subplots(figsize=(10, 6))
        
        sns.barplot(
            data=shap_df.head(15),
            x="mean_abs_shap",
            y="feature",
            palette="viridis",
            ax=ax,
        )
        ax.set_xlabel("Mean |SHAP Value| (Global Importance)")
        ax.set_ylabel("Feature")
        ax.set_title("Top 15 Most Important Features")

        plt.savefig(self.output_dir / filename)
        plt.close()

    def plot_robustness(
        self,
        robustness_df: pd.DataFrame,
        filename: str = "robustness_degradation.pdf",
    ) -> None:
        """Plot F1 score degradation under noise."""
        logger.info(f"Generating Robustness Plot: {filename}")
        fig, ax = plt.subplots(figsize=(8, 5))
        
        sns.lineplot(
            data=robustness_df,
            x="noise_level",
            y="f1_macro",
            marker="o",
            lw=2,
            ax=ax,
        )
        ax.set_xlabel("Noise Injection Level (\% of Feature Std Dev)")
        ax.set_ylabel("F1 Score (Macro)")
        ax.set_title("Model Robustness Under Evasion Simulation")
        
        plt.savefig(self.output_dir / filename)
        plt.close()
