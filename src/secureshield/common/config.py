"""
secureshield.common.config
==========================
Configuration loader — reads experiment.yaml and exposes a typed Config object.
Supports environment variable overrides via ${VAR:default} syntax.
"""

from __future__ import annotations

import os
import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Environment variable interpolation in YAML values
# ---------------------------------------------------------------------------

def _interpolate_env(value: Any) -> Any:
    """Resolve ${VAR:default} placeholders in string values."""
    if not isinstance(value, str):
        return value
    pattern = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::([^}]*))?\}")

    def replace(m: re.Match) -> str:
        var_name, default = m.group(1), m.group(2) or ""
        return os.environ.get(var_name, default)

    return pattern.sub(replace, value)


def _interpolate_dict(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: _interpolate_dict(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_interpolate_dict(v) for v in d]
    return _interpolate_env(d)


# ---------------------------------------------------------------------------
# Typed configuration sections
# ---------------------------------------------------------------------------

@dataclass
class DataConfig:
    raw_csv: str
    label_column: str = "Class"
    leakage_columns: List[str] = field(default_factory=lambda: ["Category", "Filename"])
    selected_features: List[str] = field(default_factory=list)
    test_size: float = 0.20
    val_size: float = 0.10
    stratify: bool = True
    random_state: int = 42
    scaler: str = "RobustScaler"
    fill_na_strategy: str = "zero"
    remove_zero_variance: bool = True
    check_duplicates: bool = True
    processed_dir: str = "data/processed"


@dataclass
class CorrelationWeights:
    temporal: float = 0.20
    process_relationship: float = 0.25
    file_relationship: float = 0.15
    network_relationship: float = 0.15
    evidence_confidence: float = 0.15
    ml_confidence: float = 0.10


@dataclass
class RiskConfig:
    model: str = "heuristic_v1"
    thresholds: Dict[str, int] = field(default_factory=lambda: {
        "low": 30, "medium": 55, "high": 75, "critical": 90
    })
    signals: Dict[str, int] = field(default_factory=lambda: {
        "ml_malicious": 20,
        "forensic_evidence": 15,
        "process_chain": 15,
        "external_network": 10,
        "att_ck_technique": 8,
        "persistence_indicator": 12,
        "command_execution": 10,
        "payload_execution": 10,
    })


@dataclass
class Config:
    """Flat, typed configuration object derived from experiment YAML."""
    # Project
    project_name: str = "SecureShield"
    version: str = "0.1.0"
    seed: int = 42

    # Data
    data: DataConfig = field(default_factory=DataConfig)

    # Correlation
    correlation_weights: CorrelationWeights = field(default_factory=CorrelationWeights)
    temporal_window_seconds: int = 30
    min_correlation_score: float = 0.30

    # MITRE
    mitre_require_evidence: bool = True
    mitre_min_confidence: float = 0.50

    # Risk
    risk: RiskConfig = field(default_factory=RiskConfig)

    # HPO
    hpo_n_trials: int = 30
    hpo_timeout_sec: int = 600
    hpo_primary_model: str = "LightGBM"

    # Explainability
    shap_max_samples: int = 500

    # Output paths
    models_dir: str = "models"
    figures_dir: str = "experiments/results/figures"
    tables_dir: str = "experiments/results/tables"
    reports_dir: str = "experiments/results/reports"
    logs_dir: str = "logs"


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(config_path: str | Path = "configs/experiment.yaml") -> Config:
    """
    Load and validate the experiment YAML configuration.

    Args:
        config_path: Path to the YAML config file.

    Returns:
        Populated Config dataclass.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path.resolve()}")

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    raw = _interpolate_dict(raw)

    # Build DataConfig
    d = raw.get("data", {})
    split = d.get("split", {})
    prep = d.get("preprocessing", {})
    data_cfg = DataConfig(
        raw_csv=d.get("raw_csv", ""),
        label_column=d.get("label_column", "Class"),
        leakage_columns=d.get("leakage_columns", ["Category", "Filename"]),
        selected_features=d.get("selected_features", []),
        test_size=split.get("test_size", 0.20),
        val_size=split.get("val_size", 0.10),
        stratify=split.get("stratify", True),
        random_state=split.get("random_state", 42),
        scaler=prep.get("scaler", "RobustScaler"),
        fill_na_strategy=prep.get("fill_na_strategy", "zero"),
        remove_zero_variance=prep.get("remove_zero_variance", True),
        check_duplicates=prep.get("check_duplicates", True),
        processed_dir=d.get("processed_dir", "data/processed"),
    )

    # Build CorrelationWeights
    c = raw.get("correlation", {})
    cw = CorrelationWeights(**c.get("weights", {}))

    # Build RiskConfig
    r = raw.get("risk", {})
    risk_cfg = RiskConfig(
        model=r.get("model", "heuristic_v1"),
        thresholds=r.get("thresholds", {"low": 30, "medium": 55, "high": 75, "critical": 90}),
        signals=r.get("signals", {
            "ml_malicious": 20, "forensic_evidence": 15, "process_chain": 15,
            "external_network": 10, "att_ck_technique": 8, "persistence_indicator": 12,
            "command_execution": 10, "payload_execution": 10
        }),
    )

    proj = raw.get("project", {})
    hpo = raw.get("hpo", {})
    xai = raw.get("explainability", {})
    out = raw.get("outputs", {})
    mitre = raw.get("mitre", {})

    return Config(
        project_name=proj.get("name", "SecureShield"),
        version=proj.get("version", "0.1.0"),
        seed=proj.get("seed", 42),
        data=data_cfg,
        correlation_weights=cw,
        temporal_window_seconds=c.get("temporal_window_seconds", 30),
        min_correlation_score=c.get("min_correlation_score", 0.30),
        mitre_require_evidence=mitre.get("require_evidence", True),
        mitre_min_confidence=mitre.get("min_confidence", 0.50),
        risk=risk_cfg,
        hpo_n_trials=hpo.get("n_trials", 30),
        hpo_timeout_sec=hpo.get("timeout_sec", 600),
        hpo_primary_model=hpo.get("primary_model", "LightGBM"),
        shap_max_samples=xai.get("shap", {}).get("max_samples", 500),
        models_dir=out.get("models_dir", "models"),
        figures_dir=out.get("figures_dir", "experiments/results/figures"),
        tables_dir=out.get("tables_dir", "experiments/results/tables"),
        reports_dir=out.get("reports_dir", "experiments/results/reports"),
        logs_dir=out.get("logs_dir", "logs"),
    )
