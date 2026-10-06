"""
secureshield.pipeline
======================
Main integration pipeline for the SecureShield project.

Orchestrates the entire research workflow:
  1. Data Loading & Profiling
  2. Deterministic Preprocessing
  3. Model Training & Evaluation
  4. Explainability (SHAP)
  5. Forensic Event Generation (Synthetic approximation)
  6. Multi-dimensional Correlation
  7. Risk Assessment & Response Playbooks
  8. Final Report Generation (Paper outputs)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Any

import pandas as pd

from secureshield.common.config import load_config
from secureshield.common.logging_utils import get_logger
from secureshield.data.loader import load_raw_dataset
from secureshield.preprocessing.pipeline import MalMemPreprocessor
from secureshield.detection.trainer import DetectionTrainer
from secureshield.explainability.shap_explainer import MalwareExplainer
from secureshield.forensics.normalizer import EventNormalizer
from secureshield.correlation.engine import CorrelationEngine
from secureshield.risk.scoring import RiskAssessor
from secureshield.response.playbooks import ResponseRecommender
from secureshield.timeline.reconstructor import TimelineReconstructor
from secureshield.mitre.mapper import MITREMapper
from secureshield.evaluation.robustness import RobustnessEvaluator
from secureshield.evaluation.figures import FigureGenerator

logger = get_logger(__name__)

def run_pipeline(config_path: str = "configs/experiment.yaml"):
    """Run the complete end-to-end SecureShield pipeline."""
    # 0. Setup
    config = load_config(config_path)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
    logger.info("Starting SecureShield Pipeline")
    
    # Ensure output directories exist
    Path(config.models_dir).mkdir(parents=True, exist_ok=True)
    Path(config.tables_dir).mkdir(parents=True, exist_ok=True)
    Path(config.figures_dir).mkdir(parents=True, exist_ok=True)

    # 1. Data Loading
    df, meta = load_raw_dataset(config.data.raw_csv)

    # 2. Preprocessing
    preprocessor = MalMemPreprocessor(
        test_size=config.data.test_size,
        val_size=config.data.val_size,
        random_state=config.seed,
    )
    X_train, X_val, X_test, y_train, y_val, y_test = preprocessor.fit_transform(df)
    preprocessor.save(config.models_dir)

    # 3. Model Training
    trainer = DetectionTrainer(seed=config.seed, models_dir=config.models_dir)
    results = trainer.train_and_evaluate(X_train, y_train, X_val, y_val, X_test, y_test)
    trainer.save_results(config.models_dir)

    best_model_name, best_model = trainer.get_best_model(metric="roc_auc")
    
    # 4. Explainability (SHAP)
    explainer = MalwareExplainer(model=best_model, feature_names=preprocessor.selected_features_)
    shap_values = explainer.compute_shap_values(X_test, use_samples=min(500, len(X_test)))
    shap_df = explainer.global_feature_importance()
    explainer.save(config.tables_dir)

    # 5. Figure Generation
    fig_gen = FigureGenerator(config.figures_dir)
    fig_gen.plot_shap_summary(shap_df)
    
    # Plot ROC for all models
    y_probs = {}
    for name, res in results.items():
        if "error" not in res and hasattr(res["model"], "predict_proba"):
            y_probs[name] = res["model"].predict_proba(X_test)[:, 1]
    if y_probs:
        fig_gen.plot_roc_curve(y_test, y_probs)

    # Plot Confusion Matrix for Best Model
    y_pred_best = best_model.predict(X_test)
    fig_gen.plot_confusion_matrix(y_test, y_pred_best, best_model_name)

    # 6. Robustness Evaluation
    rob_eval = RobustnessEvaluator(model=best_model, scaler=preprocessor.scaler)
    
    # Correctly map the raw test set using preprocessor's chosen subset and the split fraction 
    X_test_raw = pd.DataFrame(preprocessor.scaler.inverse_transform(X_test), columns=preprocessor.selected_features_)
    y_test_series = pd.Series(y_test)
    
    rob_df = rob_eval.evaluate_noise_injection(X_test_raw, y_test_series)
    fig_gen.plot_robustness(rob_df)

    # 7. Forensic Normalization & Correlation Simulation
    logger.info("Simulating Forensic Incident from test set...")
    malware_indices = [i for i, y in enumerate(y_test) if y == 1][:5]
    
    normalizer = EventNormalizer()
    correlation_engine = CorrelationEngine()
    
    all_events = []
    for idx in malware_indices:
        row_raw = X_test_raw.iloc[idx].to_dict()
        pred = "malicious" if y_pred_best[idx] == 1 else "benign"
        conf = float(y_probs[best_model_name][idx]) if best_model_name in y_probs else 0.9

        ml_event = normalizer.normalize_ml_prediction(
            prediction=pred,
            confidence=conf,
            model_name=best_model_name,
            top_features=[],
            evidence_id=f"ML-{idx}",
        )
        all_events.append(ml_event)

        vol_events = normalizer.normalize_volatility_row(row_raw, row_index=idx, label=1)
        all_events.extend(vol_events)

    # Correlate
    incidents = correlation_engine.correlate(all_events)
    
    # 8. Risk, MITRE, and Response
    risk_assessor = RiskAssessor()
    mitre_mapper = MITREMapper()
    responder = ResponseRecommender()
    timeline_rec = TimelineReconstructor()

    if incidents:
        primary_incident = incidents[0]
        
        mitre_mapper.map_incident(primary_incident)
        risk_assessor.assess(primary_incident)
        responder.recommend(primary_incident)
        
        timeline = timeline_rec.reconstruct(primary_incident)
        timeline_rec.save(timeline, primary_incident, config.reports_dir)
        
        logger.info(f"Pipeline Complete. Primary Incident Risk: {primary_incident.risk_level}")
    else:
        logger.warning("No incidents correlated.")

    logger.info("SecureShield End-to-End Pipeline Finished successfully.")


if __name__ == "__main__":
    run_pipeline()
