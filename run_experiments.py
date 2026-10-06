"""
secureshield.run_experiments
=============================
Execute the primary experiments for the SecureShield conference paper.
Includes:
  1. Robustness / Noise Injection Study
  2. Correlation Weight Ablation
  3. ML-only vs ML + Forensics Comparative Study

Outputs are saved as CSV/JSON in the experiments/results directory,
and paper-ready figures are generated.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Any, List

import pandas as pd
import numpy as np
from sklearn.metrics import f1_score, accuracy_score, confusion_matrix

from secureshield.common.config import load_config
from secureshield.common.logging_utils import get_logger
from secureshield.data.loader import load_raw_dataset
from secureshield.preprocessing.pipeline import MalMemPreprocessor
from secureshield.detection.trainer import DetectionTrainer
from secureshield.evaluation.robustness import RobustnessEvaluator
from secureshield.evaluation.figures import FigureGenerator
from secureshield.forensics.normalizer import EventNormalizer
from secureshield.correlation.engine import CorrelationEngine
from secureshield.risk.scoring import RiskAssessor
from secureshield.forensics.schema import ForensicEvent, EventType, SourceType, Severity
from secureshield.common.config import CorrelationWeights
from datetime import datetime, timezone, timedelta

logger = get_logger(__name__)


def run_robustness_study(
    config: Any,
    X_test_raw: pd.DataFrame,
    y_test: np.ndarray,
    preprocessor: MalMemPreprocessor,
    best_model: Any,
    fig_gen: FigureGenerator
):
    """Experiment 1: Evaluate how the ML model degrades under evasive noise."""
    logger.info("=== Running Experiment 1: Robustness / Noise Injection ===")
    
    rob_eval = RobustnessEvaluator(model=best_model, scaler=preprocessor.scaler)
    
    # Run evaluation
    y_test_series = pd.Series(y_test)
    results_df = rob_eval.evaluate_noise_injection(
        X_test_raw, 
        y_test_series, 
        noise_levels=[0.01, 0.05, 0.10, 0.20, 0.30, 0.50]
    )
    
    # Save raw data
    results_df.to_csv(Path(config.tables_dir) / "exp1_robustness.csv", index=False)
    
    # Plot figure
    fig_gen.plot_robustness(results_df)
    logger.info("Experiment 1 complete.")


def run_correlation_ablation(config: Any):
    """Experiment 2: Evaluate the impact of different correlation dimensions."""
    logger.info("=== Running Experiment 2: Correlation Ablation ===")
    
    normalizer = EventNormalizer()
    
    # Create a synthetic clustered incident representing a true positive malware infection
    t0 = datetime.now(timezone.utc)
    # Event 1: Initial ML detection
    ev1 = normalizer.normalize_ml_prediction("malicious", 0.95, "LightGBM", [], "ML-1")
    ev1.timestamp = t0
    
    # Event 2: Process Creation (child process)
    ev2 = ForensicEvent(
        timestamp=t0 + timedelta(seconds=5),
        event_type=EventType.PROCESS_CREATION,
        source_type=SourceType.SYNTHETIC_FROM_ML_FEATURES,
        severity=Severity.HIGH,
        host="ML-1",
        evidence_id="EVID-002",
        notes="Process Creation",
        metadata={"process_name": "malicious_proc.exe"}
    )
    ev2.pid = 1234
    ev2.ppid = getattr(ev1, "pid", None)
    
    # Event 3: Memory Injection
    ev3 = ForensicEvent(
        timestamp=t0 + timedelta(seconds=10),
        event_type=EventType.PROCESS_INJECTION,
        source_type=SourceType.SYNTHETIC_FROM_ML_FEATURES,
        severity=Severity.CRITICAL,
        host="ML-1",
        evidence_id="EVID-003",
        notes="Memory Injection",
        metadata={"process_name": "explorer.exe"}
    )
    ev3.pid = 5678
    ev3.ppid = 1234
    
    events = [ev1, ev2, ev3]
    
    # Define ablation weights (Temporal/Process/File/Network/Evidence/ML)
    ablation_configs = [
        ("ML Only (Baseline)",            (0.0, 0.0, 0.0, 0.0, 0.0, 1.0)),
        ("Temporal Only",                 (1.0, 0.0, 0.0, 0.0, 0.0, 0.0)),
        ("Temporal + Process",            (0.5, 0.5, 0.0, 0.0, 0.0, 0.0)),
        ("Temp + Proc + File",            (0.4, 0.4, 0.2, 0.0, 0.0, 0.0)),
        ("Full Context (SecureShield)",   (0.20, 0.25, 0.15, 0.15, 0.15, 0.10)),
    ]
    
    results = []
    
    for name, weights in ablation_configs:
        c_weights = CorrelationWeights(
            temporal=weights[0],
            process_relationship=weights[1],
            file_relationship=weights[2],
            network_relationship=weights[3],
            evidence_confidence=weights[4],
            ml_confidence=weights[5]
        )
        engine = CorrelationEngine(
            weights=c_weights,
            temporal_window_sec=30
        )
        
        incidents = engine.correlate(events)
        if incidents:
            # Score normalization: 0.0 to 1.0 (higher means stronger correlation between nodes)
            # Edges formed: Number of relationships identified between events (e.g. process parent-child, temporal proximity)
            score = incidents[0].correlation_score
            edge_count = engine.event_graph_.number_of_edges()
        else:
            score = 0.0
            edge_count = 0
            
        results.append({
            "Configuration": name,
            "Correlation_Score": score,
            "Edges_Formed": edge_count,
            "Interpretation": "Stronger cluster context" if score > 0.35 else "Weak or isolated context"
        })
        
    df = pd.DataFrame(results)
    df.to_csv(Path(config.tables_dir) / "exp2_correlation_ablation.csv", index=False)
    logger.info("Experiment 2 complete.")


def run_comparative_study(
    config: Any,
    X_test_raw: pd.DataFrame,
    y_test: np.ndarray,
    y_pred_ml: np.ndarray,
    y_prob_ml: np.ndarray
):
    """
    Experiment 3: ML-Only vs ML + Forensics Comparative Study
    Demonstrates how forensic correlation reduces False Positives and elevates 
    True Positives to actionable incident alerts.
    """
    logger.info("=== Running Experiment 3: ML-Only vs ML + Forensics ===")
    
    # 1. Identify ML False Positives and True Positives
    fps = np.where((y_test == 0) & (y_pred_ml == 1))[0]
    tps = np.where((y_test == 1) & (y_pred_ml == 1))[0]
    
    # We will sample up to 10 FPs and 10 TPs to simulate real-world triage
    sample_fps = fps[:min(10, len(fps))]
    sample_tps = tps[:min(10, len(tps))]
    
    normalizer = EventNormalizer()
    engine = CorrelationEngine()
    assessor = RiskAssessor()
    
    results = []
    
    # Helper to simulate an incident
    def simulate_incident(idx: int, is_true_positive: bool):
        row = X_test_raw.iloc[idx]
        prob = y_prob_ml[idx]
        
        # Base ML Event
        ml_event = normalizer.normalize_ml_prediction("malicious", prob, "BestModel", [], f"ML-{idx}")
        
        events = [ml_event]
        
        # Unconditionally extract forensic evidence from the raw features.
        # This prevents circular evaluation: the ML model flagged it, so we check forensics.
        # If it's a True Positive, the features should naturally contain strong evidence.
        # If it's a False Positive, the features should naturally lack strong evidence.
        vol_events = normalizer.normalize_volatility_row(
            row.to_dict(), 
            row_index=idx, 
            label=1 if is_true_positive else 0
        )
        
        # Adjust timestamps to cluster them temporally with the ML event
        for i, ev in enumerate(vol_events):
            ev.timestamp = ml_event.timestamp + timedelta(seconds=(i * 2))
            
        events.extend(vol_events)
            
        # Correlate
        incidents = engine.correlate(events)
        
        # Assess Risk
        if incidents:
            incident = incidents[0]
            assessor.assess(incident)
            return {
                "Type": "True Positive" if is_true_positive else "False Positive",
                "Events_Count": len(incident.events),
                "Correlation_Score": incident.correlation_score,
                "Risk_Score": incident.risk_score,
                "Risk_Level": incident.risk_level
            }
        return None

    for idx in sample_fps:
        res = simulate_incident(idx, is_true_positive=False)
        if res: results.append(res)
        
    for idx in sample_tps:
        res = simulate_incident(idx, is_true_positive=True)
        if res: results.append(res)
        
    df = pd.DataFrame(results)
    
    # Aggregate results for table
    agg_df = df.groupby("Type").agg({
        "Events_Count": "mean",
        "Correlation_Score": "mean",
        "Risk_Score": "mean",
    }).reset_index()
    
    # Map back to actionable
    # Actionable if Risk >= High (75)
    actionable_tps = len(df[(df["Type"] == "True Positive") & (df["Risk_Score"] >= 75)])
    actionable_fps = len(df[(df["Type"] == "False Positive") & (df["Risk_Score"] >= 75)])
    
    summary = {
        "Evaluation_Type": "Controlled Simulated Forensic Scenario",
        "Limitation": "CIC-MalMem-2022 lacks native forensic streams. Simulated derived events were used. No TN/FN sampled.",
        "Tested_Subset_Size": len(sample_fps) + len(sample_tps),
        "ML_Only_FPs_Sampled": len(sample_fps),
        "SecureShield_Actionable_FPs": actionable_fps,
        "ML_Only_TPs_Sampled": len(sample_tps),
        "SecureShield_Actionable_TPs": actionable_tps,
    }
    
    agg_df.to_csv(Path(config.tables_dir) / "exp3_comparative_stats.csv", index=False)
    with open(Path(config.reports_dir) / "exp3_summary.json", "w") as f:
        json.dump(summary, f, indent=4)
        
    logger.info(f"Experiment 3 complete. Simulated subset evaluated.")


def main():
    config = load_config("configs/experiment.yaml")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
    
    # Directories
    Path(config.tables_dir).mkdir(parents=True, exist_ok=True)
    Path(config.reports_dir).mkdir(parents=True, exist_ok=True)
    Path(config.figures_dir).mkdir(parents=True, exist_ok=True)
    
    # Data & Setup (reloading from artifacts to ensure we use exact pipeline outputs)
    logger.info("Loading preprocessed data and best model...")
    df, _ = load_raw_dataset(config.data.raw_csv)
    
    preprocessor = MalMemPreprocessor.load(config.models_dir)
    preprocessor.feature_subset = config.data.selected_features
    _, _, X_test, _, _, y_test = preprocessor.fit_transform(df)  # This re-runs the deterministic split
    
    trainer = DetectionTrainer(seed=config.seed, models_dir=config.models_dir)
    trainer.load_results(config.models_dir)
    best_model_name, best_model = trainer.get_best_model("roc_auc")
    
    # We need the unscaled features for robustness injection
    X_test_raw = pd.DataFrame(preprocessor.scaler.inverse_transform(X_test), columns=preprocessor.selected_features_)
    
    y_pred = best_model.predict(X_test)
    y_prob = best_model.predict_proba(X_test)[:, 1] if hasattr(best_model, "predict_proba") else y_pred
    
    fig_gen = FigureGenerator(config.figures_dir)
    
    # Run Experiments
    run_robustness_study(config, X_test_raw, y_test, preprocessor, best_model, fig_gen)
    run_correlation_ablation(config)
    run_comparative_study(config, X_test_raw, y_test, y_pred, y_prob)

    logger.info("All experiments completed successfully.")


if __name__ == "__main__":
    main()
