"""
secureshield.detection.hpo
===========================
Reproducible hyperparameter optimization using Optuna TPE.

Design principles:
- Optimization uses ONLY the training/validation split — never the test set
- Best parameters stored with experiment metadata
- Study saved to SQLite for inspection/resumption
- Seeds fixed for reproducibility
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

try:
    import optuna
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    HAS_OPTUNA = True
except ImportError:
    HAS_OPTUNA = False

try:
    from lightgbm import LGBMClassifier
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False

from sklearn.model_selection import cross_val_score

from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Search spaces
# ---------------------------------------------------------------------------

SEARCH_SPACES = {
    "LightGBM": {
        "n_estimators": ("int", 50, 300),
        "max_depth": ("int", 3, 12),
        "num_leaves": ("int", 15, 127),
        "learning_rate": ("float_log", 0.01, 0.3),
        "min_child_samples": ("int", 10, 100),
        "subsample": ("float", 0.5, 1.0),
        "colsample_bytree": ("float", 0.5, 1.0),
        "reg_alpha": ("float_log", 1e-6, 1.0),
        "reg_lambda": ("float_log", 1e-6, 1.0),
    },
    "RandomForest": {
        "n_estimators": ("int", 50, 300),
        "max_depth": ("int", 3, 20),
        "min_samples_split": ("int", 2, 20),
        "min_samples_leaf": ("int", 1, 10),
        "max_features": ("categorical", ["sqrt", "log2"]),
    },
    "XGBoost": {
        "n_estimators": ("int", 50, 300),
        "max_depth": ("int", 3, 10),
        "learning_rate": ("float_log", 0.01, 0.3),
        "subsample": ("float", 0.5, 1.0),
        "colsample_bytree": ("float", 0.5, 1.0),
        "reg_alpha": ("float_log", 1e-6, 1.0),
        "reg_lambda": ("float_log", 1e-6, 1.0),
    },
}


def _suggest_param(trial: Any, name: str, spec: tuple) -> Any:
    """Suggest a hyperparameter value based on its spec."""
    kind = spec[0]
    if kind == "int":
        return trial.suggest_int(name, spec[1], spec[2])
    elif kind == "float":
        return trial.suggest_float(name, spec[1], spec[2])
    elif kind == "float_log":
        return trial.suggest_float(name, spec[1], spec[2], log=True)
    elif kind == "categorical":
        return trial.suggest_categorical(name, spec[1])
    raise ValueError(f"Unknown parameter kind: {kind}")


# ---------------------------------------------------------------------------
# HPO runner
# ---------------------------------------------------------------------------

class HyperparameterOptimizer:
    """
    Optuna-based HPO for SecureShield detection models.

    Optimization is performed on the training set via cross-validation.
    The test set is NEVER touched during HPO.
    """

    def __init__(
        self,
        model_name: str = "LightGBM",
        n_trials: int = 30,
        timeout_sec: int = 600,
        cv_folds: int = 3,
        scoring: str = "roc_auc",
        seed: int = 42,
        storage: Optional[str] = None,
    ):
        self.model_name = model_name
        self.n_trials = n_trials
        self.timeout_sec = timeout_sec
        self.cv_folds = cv_folds
        self.scoring = scoring
        self.seed = seed
        self.storage = storage
        self.best_params_: Dict[str, Any] = {}
        self.best_value_: float = 0.0
        self.study_ = None

    def _build_model(self, params: Dict[str, Any]) -> Any:
        """Instantiate the model with given params."""
        if self.model_name == "LightGBM" and HAS_LGBM:
            return LGBMClassifier(**params, random_state=self.seed, n_jobs=1, verbose=-1)
        elif self.model_name == "RandomForest":
            from sklearn.ensemble import RandomForestClassifier
            return RandomForestClassifier(**params, random_state=self.seed, n_jobs=-1)
        elif self.model_name == "XGBoost":
            from xgboost import XGBClassifier
            return XGBClassifier(**params, random_state=self.seed, n_jobs=-1,
                                eval_metric="logloss", verbosity=0)
        raise ValueError(f"Unsupported model for HPO: {self.model_name}")

    def optimize(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Run Optuna TPE optimization on training data via cross-validation.

        IMPORTANT: X_test / y_test are NEVER passed here.
        Optimization uses ONLY the training partition.

        Args:
            X_train: Training features.
            y_train: Training labels.

        Returns:
            Best hyperparameters dict.
        """
        if not HAS_OPTUNA:
            logger.warning("Optuna not installed — skipping HPO.")
            return {}

        search_space = SEARCH_SPACES.get(self.model_name, {})
        if not search_space:
            logger.warning(f"No search space defined for {self.model_name}.")
            return {}

        logger.info(
            f"HPO: {self.model_name}, {self.n_trials} trials, "
            f"timeout={self.timeout_sec}s, scoring={self.scoring}"
        )

        def objective(trial: optuna.Trial) -> float:
            params = {
                name: _suggest_param(trial, name, spec)
                for name, spec in search_space.items()
            }
            model = self._build_model(params)
            try:
                scores = cross_val_score(
                    model, X_train, y_train,
                    cv=self.cv_folds,
                    scoring=self.scoring,
                    n_jobs=1,
                )
                return float(scores.mean())
            except Exception:
                return 0.0

        sampler = optuna.samplers.TPESampler(seed=self.seed)
        study = optuna.create_study(
            direction="maximize",
            sampler=sampler,
            study_name=f"secureshield_{self.model_name.lower()}",
            storage=self.storage,
            load_if_exists=True,
        )
        study.optimize(
            objective,
            n_trials=self.n_trials,
            timeout=self.timeout_sec,
            show_progress_bar=False,
        )

        self.study_ = study
        self.best_params_ = study.best_params
        self.best_value_ = study.best_value

        logger.info(f"Best {self.scoring}: {self.best_value_:.4f}")
        logger.info(f"Best params: {self.best_params_}")

        return self.best_params_

    def save(self, output_dir: str | Path) -> None:
        """Save HPO results for reproducibility."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        result = {
            "model": self.model_name,
            "n_trials": self.n_trials,
            "seed": self.seed,
            "scoring": self.scoring,
            "best_value": self.best_value_,
            "best_params": self.best_params_,
            "search_space": SEARCH_SPACES.get(self.model_name, {}),
            "note": (
                "HPO performed on training set via cross-validation only. "
                "Test set was not used in any HPO trial."
            ),
        }
        out_path = output_dir / f"hpo_{self.model_name.lower()}.json"
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        logger.info(f"HPO results saved: {out_path}")
