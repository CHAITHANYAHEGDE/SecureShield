# Research Methodology and Integrity

SecureShield's primary focus is demonstrating the limitations of purely statistical ML classification in Endpoint Detection and Response (EDR) contexts, and proposing a structural forensic correlation approach.

## Experimental Framework
All experiments operate on a deterministically seeded 80/20 train/test split. No test data leaks into the training pipeline. The CIC-MalMem-2022 dataset provides a heavily curated set of numerical endpoint artifacts.

### The Problem with 1.000 AUC
Our models easily achieve perfect ROC AUC on the test set. However, examining the SHAP values indicates this is due to **dataset-specific feature separability**—a distributional artifact resulting from the extremely controlled nature of the malware detonation environment compared to the benign background state. This implies that high offline performance on such datasets is not necessarily indicative of true real-world efficacy.

### Methodology & Limitations
To explore this without native telemetry, we implement:
1. **Feature-Perturbation Robustness Stress Test**: Gaussian noise injected at varying thresholds degrades the ML F1-score aggressively, underscoring the fragility of static numerical thresholds. This is an analytical stress test, not proof of real-world adversarial robustness.
2. **Controlled Simulated Forensic Scenario**: We synthetically simulate an environment where structural events are conditionally bound to the numerical values of the dataset. This explicitly acts as a *simulation* to demonstrate the correlation methodology. No True Negative or False Negative claims are made from this isolated subset. All results carry limited external validity until deployed on real-world native telemetry.
