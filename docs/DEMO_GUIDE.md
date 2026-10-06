# Conference Demonstration Guide

This guide outlines a 5–10 minute demonstration flow for presenting SecureShield's research capabilities.

## Step 1: Dashboard Overview
1. Start at the main Dashboard page.
2. Explain the goal: Correlating ML detections with structural forensic data to reduce actionable false positives.

## Step 2: Malware Sample Analysis
1. Select a specific sample index from the provided dropdowns (e.g., a known True Positive).
2. Click **Analyze**.
3. Point out the instantaneous ML baseline detection and probability score.

## Step 3: SHAP Explanation
1. Navigate to the **Explainability (SHAP)** pane.
2. Demonstrate how SecureShield attributes the ML decision to highly separable numerical dataset features (e.g., `svcscan.nservices`).

## Step 4: Forensic Evidence
1. Navigate to the **Forensic Evidence** tab.
2. Highlight the `SIMULATED` and `DERIVED` provenance markers to maintain scientific transparency.
3. Show the structural edge connections that have been mathematically synthesized.

## Step 5: Incident Timeline
1. Switch to the **Attack Timeline** view.
2. Walk the audience through the progression from Initial Access through Execution.

## Step 6: MITRE ATT&CK Mapping
1. View the **MITRE Mapping**.
2. Correlate the timeline events to the formal MITRE taxonomy. Note how no technique is assigned without backing evidence.

## Step 7: Risk & Response
1. View the final **Risk Assessment**.
2. Note the numerical score and how it dictates the Response Playbook execution.

## Step 8: Research Results
1. Navigate to the **Research Results** tab.
2. Walk the audience through the `Feature-Perturbation Stress Test` to prove threshold fragility.
3. Conclude with the `Comparative Stats` section, visually demonstrating the reduction of ML-only False Positives to 0/10 via SecureShield's correlation.
