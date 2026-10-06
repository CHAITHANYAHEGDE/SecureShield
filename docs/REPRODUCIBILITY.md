# Reproducibility Guide

To maintain scientific integrity, the entirety of SecureShield's core claims can be regenerated deterministically.

## 1. Prerequisites
Ensure you have Python 3.9+ installed and a virtual environment active.
Dependencies: `pandas`, `scikit-learn`, `shap`, `networkx`, `fastapi`, `uvicorn`.

## 2. Generating Research Data
From the repository root:
```bash
export PYTHONPATH=src
python3 run_experiments.py
```
This script will sequentially:
1. Load and parse the dataset.
2. Filter the 14 defined separability features.
3. Train the models.
4. Execute Experiment 1: Robustness Stress Test.
5. Execute Experiment 2: Correlation Ablation.
6. Execute Experiment 3: Comparative Stats (10 TP / 10 FP).
7. Save `.csv` and `.json` artifacts inside `experiments/results/tables/` and `experiments/results/reports/`.

## 3. Verifying the Backend
Ensure the backend provenance tests pass:
```bash
export PYTHONPATH=src
pytest
```

## 4. Building the Frontend
To verify the React application builds cleanly for production:
```bash
cd frontend
npm install
npm run build
```
