# System Architecture

SecureShield's architecture leverages offline machine learning outputs to simulate an advanced SOC (Security Operations Center) environment. The architecture is focused on a Python data/research pipeline.

## 1. Data Pipeline (`src/secureshield/`)
The foundational data logic is defined in Python. It handles:
- Dataset ingestion and normalization.
- Machine Learning (RandomForest) prediction and probability assessment.
- SHAP (SHapley Additive exPlanations) values to extract individual feature contributions.
- The **Forensic Normalization Layer** creates simulated temporal and structural events to augment the purely numerical ML inputs.
- The **Correlation Engine** uses NetworkX graphs to build connected edge sets representing full incident context.
- The **Risk Scoring & MITRE Mapping Engine** assigns specific TTPs and final triage priorities based on the established evidence.


