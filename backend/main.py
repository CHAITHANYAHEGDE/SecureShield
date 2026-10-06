from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import numpy as np
import joblib
import json
import os
from pathlib import Path

# Add src to python path for imports
import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

app = FastAPI(title="SecureShield API")

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["X-Frame-Options"] = "DENY"
        return response

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("SECURESHIELD_FRONTEND_URL", "http://localhost:3000,http://127.0.0.1:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

PROJECT_ROOT = Path(__file__).parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"

from pydantic import BaseModel, Field

class AnalyzeRequest(BaseModel):
    sample_id: str = Field(..., pattern=r'^\d+$', max_length=10, description="Numeric index of the sample")

@app.get("/api/samples")
def get_samples():
    """Return a list of available demo samples."""
    try:
        df = pd.read_csv(os.environ.get("SECURESHIELD_DATASET", PROJECT_ROOT / "data" / "raw" / "MalMem2022_Binary_Clean.csv"))
        benign = df[df['Class'] == 0].head(2)
        malicious = df[df['Class'] == 1].head(2)
        samples = pd.concat([benign, malicious])
        return [
            {"id": str(i), "class": "benign" if row['Class'] == 0 else "malicious", "features": row.to_dict()}
            for i, row in samples.iterrows()
        ]
    except Exception:
        return {"error": "Failed to load samples."}

@app.get("/api/models")
def get_models():
    perf_file = RESULTS_DIR / "tables" / "model_performance.csv"
    if not perf_file.exists():
        raise HTTPException(status_code=404, detail="Model performance not found")
    df = pd.read_csv(perf_file)
    return df.to_dict(orient="records")

@app.get("/api/metrics")
def get_metrics():
    cv_file = RESULTS_DIR / "tables" / "cv_results.csv"
    if not cv_file.exists():
        raise HTTPException(status_code=404, detail="CV metrics not found")
    df = pd.read_csv(cv_file)
    return df.to_dict(orient="records")

@app.get("/api/shap/global")
def get_shap_global():
    shap_file = RESULTS_DIR / "tables" / "shap_global_importance.csv"
    if not shap_file.exists():
        raise HTTPException(status_code=404, detail="SHAP global importance not found")
    df = pd.read_csv(shap_file)
    return df.to_dict(orient="records")

@app.get("/api/experiments/robustness")
def get_robustness():
    file_path = RESULTS_DIR / "tables" / "exp1_robustness.csv"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Not found")
    return pd.read_csv(file_path).to_dict(orient="records")

@app.get("/api/experiments/ablation")
def get_ablation():
    file_path = RESULTS_DIR / "tables" / "exp2_correlation_ablation.csv"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Not found")
    return pd.read_csv(file_path).to_dict(orient="records")

@app.get("/api/experiments/comparative")
def get_comparative():
    file_path = RESULTS_DIR / "reports" / "exp3_summary.json"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Not found")
    with open(file_path, "r") as f:
        return json.load(f)

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    """
    Run the full pipeline on a single sample.
    """
    try:
        best_model_name = "randomforest"
        model = joblib.load(MODELS_DIR / f"{best_model_name}.joblib")
        scaler = joblib.load(MODELS_DIR / "scaler.joblib")
        with open(MODELS_DIR / "preprocessing_metadata.json") as f:
            meta = json.load(f)
        features_used = meta["selected_features"]
    except Exception:
        raise HTTPException(status_code=500, detail="Pipeline models not available.")

    try:
        df = pd.read_csv(os.environ.get("SECURESHIELD_DATASET", PROJECT_ROOT / "data" / "raw" / "MalMem2022_Binary_Clean.csv"))
        idx = int(req.sample_id)
        if idx >= len(df):
            raise HTTPException(status_code=404, detail="Sample not found")
        row = df.iloc[[idx]]
        true_label = row["Class"].values[0]
        drop_cols = ["Category", "Filename", "Class"]
        X_raw = row.drop(columns=[c for c in drop_cols if c in row.columns])
        X_raw = X_raw[features_used]
        
        X_scaled = scaler.transform(X_raw)
        
        prob = model.predict_proba(X_scaled)[0, 1]
        pred = model.predict(X_scaled)[0]
        
        from secureshield.explainability.shap_explainer import MalwareExplainer
        explainer = MalwareExplainer(model, feature_names=features_used)
        explainer._explainer = joblib.load(MODELS_DIR / "shap_explainer.joblib") if (MODELS_DIR/"shap_explainer.joblib").exists() else None
        
        if explainer._explainer is None:
            explainer._build_explainer(X_scaled)
        
        shap_vals = explainer.compute_shap_values(X_scaled)
        shap_out = explainer.local_explanation(0, pred, prob)

        from secureshield.forensics.normalizer import EventNormalizer
        import yaml
        with open(PROJECT_ROOT / "configs" / "experiment.yaml") as f:
            cfg = yaml.safe_load(f)
            
        normalizer = EventNormalizer()
        raw_dict = X_raw.iloc[0].to_dict()
        events = normalizer.normalize_volatility_row(raw_dict, row_index=idx, label=int(pred))
        ml_event = normalizer.normalize_ml_prediction(
            prediction="malicious" if pred == 1 else "benign",
            confidence=float(prob),
            model_name=best_model_name,
            top_features=[],
            evidence_id=f"ML-{idx}",
        )
        events.append(ml_event)
        
        from secureshield.correlation.engine import CorrelationEngine
        from secureshield.common.config import CorrelationWeights
        correlation_cfg = cfg["correlation"]
        weights = CorrelationWeights(**correlation_cfg["weights"])
        engine = CorrelationEngine(weights, correlation_cfg["min_correlation_score"])
        incidents = engine.correlate(events)
        incident = incidents[0] if incidents else None

        from secureshield.mitre.mapper import MITREMapper
        mitre_mapper = MITREMapper(cfg["mitre"]["min_confidence"])
        mitre_mappings = mitre_mapper.map_incident(incident) if incident else []

        from secureshield.risk.scoring import RiskAssessor
        risk_assessor = RiskAssessor()
        risk_assessment = risk_assessor.assess(incident) if incident else None

        from secureshield.response.playbooks import ResponseRecommender
        responder = ResponseRecommender()
        playbooks = responder.recommend(incident) if incident else {}

        from secureshield.timeline.reconstructor import TimelineReconstructor
        timeline_rec = TimelineReconstructor()
        timeline = timeline_rec.reconstruct(incident) if incident else {}
        
        evidence_list = []
        if incident:
            for ev in incident.events:
                evidence_list.append({
                    "id": ev.event_id,
                    "type": ev.event_type.value,
                    "source": ev.source_type.value,
                    "description": ev.notes or "",
                    "confidence": ev.confidence,
                    "provenance": "DERIVED" if ev.synthetic else "MEASURED"
                })

        return {
            "prediction": {
                "label": "malicious" if pred == 1 else "benign",
                "confidence": float(prob) if pred == 1 else 1.0 - float(prob),
                "model": "RandomForest",
                "provenance": "MEASURED"
            },
            "shap": shap_out.get("top_features", []),
            "evidence": evidence_list,
            "correlation": [
                {
                    "evidence_ids": [ev.event_id for ev in incident.events],
                    "rule": "Temporal + Process Clustering", 
                    "rationale": "High volume of memory anomalies within short timeframe.",
                    "provenance": "DERIVED"
                }
            ] if incident else [],
            "timeline": timeline if isinstance(timeline, list) else [],
            "mitre": [
                {
                    "tactic": m.get("tactic", ""),
                    "technique_id": m.get("technique_id", ""),
                    "sub_technique": m.get("technique", ""),
                    "supporting_evidence_ids": m.get("supporting_events", []),
                    "confidence": m.get("mapping_confidence", 0.0),
                    "rule_id": "MITRE_MAPPING",
                    "provenance": "DERIVED"
                } for m in mitre_mappings
            ],
            "risk": {
                "score": risk_assessment.get("risk_score", 0) if risk_assessment else 0,
                "severity": risk_assessment.get("risk_level", "LOW") if risk_assessment else "LOW",
                "factors": risk_assessment.get("risk_factors", []) if risk_assessment else [],
                "provenance": "DERIVED"
            },
            "response": playbooks if incident else {"containment": [], "investigation": [], "recovery": []}
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Internal analysis error.")
