# System Architecture

SecureShield's architecture leverages offline machine learning outputs to simulate an advanced SOC (Security Operations Center) environment. The architecture is modularly separated between a Python data/research pipeline, a FastAPI service layer, and a React visualization frontend.

## 1. Data Pipeline (`src/secureshield/`)
The foundational data logic is defined in Python. It handles:
- Dataset ingestion and normalization.
- Machine Learning (RandomForest) prediction and probability assessment.
- SHAP (SHapley Additive exPlanations) values to extract individual feature contributions.
- The **Forensic Normalization Layer** creates simulated temporal and structural events to augment the purely numerical ML inputs.
- The **Correlation Engine** uses NetworkX graphs to build connected edge sets representing full incident context.
- The **Risk Scoring & MITRE Mapping Engine** assigns specific TTPs and final triage priorities based on the established evidence.

## 2. API Backend (`backend/`)
Built with FastAPI, the backend operates as a read-only bridge for the dashboard. It exposes:
- `/api/analyze` - Receives a specific sample ID and simulates the full end-to-end detection, correlation, and response generation in real time.
- Standard security middlewares restrict CORS to permitted local/frontend origins and ensure paths are safely sanitized.

## 3. Frontend Dashboard (`frontend/`)
A React 19 / Vite 8 application built with TailwindCSS v4 and React Flow.
- Translates the highly complex JSON payloads from the API into distinct analytical panes (Analysis, Evidence, Mitre, Risk, Timeline).
- Adheres strictly to the Provenance system by surfacing `MEASURED`, `DERIVED`, and `SIMULATED` markers for all data elements.
