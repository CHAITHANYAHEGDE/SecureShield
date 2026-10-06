import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Set aesthetics
sns.set_theme(style="whitegrid", context="paper")
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Arial', 'Helvetica', 'sans-serif']

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLES_DIR = os.path.join(BASE_DIR, "experiments", "results", "tables")
OUTPUT_DIR = os.path.join(BASE_DIR, "docs", "images")

os.makedirs(OUTPUT_DIR, exist_ok=True)

def plot_model_performance():
    df = pd.read_csv(os.path.join(TABLES_DIR, "model_performance.csv"))
    # Filter only test set metrics if available, else use all
    if "dataset" in df.columns:
        df = df[df["dataset"] == "test"].copy()
    df = df.sort_values(by="roc_auc", ascending=True)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(df))
    width = 0.25
    
    ax.bar(x - width, df['accuracy'], width, label='Accuracy', color='#4FA36B')
    ax.bar(x, df['f1_macro'], width, label='F1-Macro', color='#D9A441')
    ax.bar(x + width, df['roc_auc'], width, label='ROC-AUC', color='#E2793B')
    
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Model Performance Comparison', fontsize=14, pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(df['model'], rotation=45, ha='right')
    ax.legend(loc='lower right')
    ax.set_ylim(0.98, 1.002) # Zoom in to see the tiny differences
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "model-performance.png"), dpi=300)
    plt.close()

def plot_shap_importance():
    df = pd.read_csv(os.path.join(TABLES_DIR, "shap_global_importance.csv"))
    df = df.head(10).sort_values(by="mean_abs_shap", ascending=True)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(df['feature'], df['mean_abs_shap'], color='#262C34')
    ax.set_xlabel('Mean |SHAP value| (average impact on model output magnitude)', fontsize=12)
    ax.set_title('SHAP Feature Importance (Top 10)', fontsize=14, pad=20)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "shap-feature-importance.png"), dpi=300)
    plt.close()

def plot_robustness():
    df = pd.read_csv(os.path.join(TABLES_DIR, "exp1_robustness.csv"))
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(df['noise_level'], df['accuracy'], marker='o', linewidth=2, label='Accuracy', color='#D64545')
    ax.plot(df['noise_level'], df['f1_macro'], marker='s', linewidth=2, label='F1-Macro', color='#E2793B')
    
    ax.set_xlabel('Gaussian Noise Level (Standard Deviations)', fontsize=12)
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Feature-Perturbation Robustness Stress Test\n(Analytical Stress Test - Not Proof of Adversarial Robustness)', fontsize=14, pad=20)
    ax.legend()
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.set_ylim(0, 1.05)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "robustness-stress-test.png"), dpi=300)
    plt.close()

def plot_correlation_ablation():
    df = pd.read_csv(os.path.join(TABLES_DIR, "exp2_correlation_ablation.csv"))
    
    fig, ax1 = plt.subplots(figsize=(10, 6))
    
    color = '#262C34'
    ax1.set_xlabel('Configuration', fontsize=12)
    ax1.set_ylabel('Normalized Forensic Relationship Confidence', color=color, fontsize=12)
    bars = ax1.bar(df['Configuration'], df['Correlation_Score'], color='#4FA36B', alpha=0.7)
    ax1.tick_params(axis='y', labelcolor=color)
    ax1.set_xticklabels(df['Configuration'], rotation=45, ha='right')
    ax1.set_ylim(0, 1.0)
    
    ax2 = ax1.twinx()
    color = '#D64545'
    ax2.set_ylabel('Edges Formed', color=color, fontsize=12)
    ax2.plot(df['Configuration'], df['Edges_Formed'], color=color, marker='o', linewidth=2, markersize=8)
    ax2.tick_params(axis='y', labelcolor=color)
    ax2.set_ylim(0, 5)
    
    plt.title('Correlation Dimension Ablation', fontsize=14, pad=20)
    fig.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "correlation-ablation.png"), dpi=300)
    plt.close()

def plot_ml_vs_secureshield():
    # ML-only FP sampled = 10
    # SecureShield actionable FP = 0
    # ML-only TP sampled = 10
    # SecureShield actionable TP = 10
    
    labels = ['False Positives', 'True Positives']
    ml_only = [10, 10]
    secureshield = [0, 10]
    
    x = np.arange(len(labels))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.bar(x - width/2, ml_only, width, label='ML Only', color='#D64545')
    ax.bar(x + width/2, secureshield, width, label='SecureShield', color='#4FA36B')
    
    ax.set_ylabel('Incident Count', fontsize=12)
    ax.set_title('Controlled Simulated Forensic Scenario\n(Subset size: 20)', fontsize=14, pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    
    # Add value labels
    for i in range(len(labels)):
        ax.text(x[i] - width/2, ml_only[i] + 0.2, str(ml_only[i]), ha='center')
        ax.text(x[i] + width/2, secureshield[i] + 0.2, str(secureshield[i]), ha='center')
        
    ax.set_ylim(0, 12)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "ml-vs-secureshield.png"), dpi=300)
    plt.close()

def plot_architecture():
    import matplotlib.patches as patches
    fig, ax = plt.subplots(figsize=(10, 12))
    ax.axis('off')
    
    stages = [
        ("CIC-MalMem-2022", "MEASURED"),
        ("Data Cleaning", "MEASURED"),
        ("Preprocessing", "MEASURED"),
        ("ML Malware Detection", "MEASURED"),
        ("SHAP Explainability", "DERIVED"),
        ("Forensic Evidence Normalization", "SIMULATED"),
        ("Event Correlation", "SIMULATED"),
        ("Incident Timeline", "SIMULATED"),
        ("Behavioral Analysis", "SIMULATED"),
        ("MITRE ATT&CK Mapping", "SIMULATED"),
        ("Risk Assessment", "SIMULATED"),
        ("Response Recommendations", "SIMULATED"),
        ("SOC Dashboard", "PRESENTATION")
    ]
    
    y = 1.0
    y_step = 0.075
    
    for text, tag in stages:
        color = '#262C34'
        if tag == "MEASURED":
            color = '#4FA36B'
        elif tag == "DERIVED":
            color = '#D9A441'
        elif tag == "SIMULATED":
            color = '#E2793B'
            
        rect = patches.Rectangle((0.3, y), 0.4, 0.05, linewidth=1, edgecolor='black', facecolor=color, alpha=0.8)
        ax.add_patch(rect)
        ax.text(0.5, y + 0.025, text, ha='center', va='center', color='white', fontweight='bold', fontsize=11)
        
        # Tag
        ax.text(0.72, y + 0.025, f"[{tag}]", ha='left', va='center', color=color, fontweight='bold', fontsize=10)
        
        if y > 1.0 - (len(stages)-1)*y_step:
            ax.annotate('', xy=(0.5, y-0.025), xytext=(0.5, y),
                        arrowprops=dict(facecolor='black', shrink=0.05, width=1, headwidth=6))
        y -= y_step
        
    plt.title('SecureShield Architecture Pipeline', fontsize=16, pad=20)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "architecture.png"), dpi=300)
    plt.close()

if __name__ == "__main__":
    print("Generating Research Plots...")
    plot_model_performance()
    plot_shap_importance()
    plot_robustness()
    plot_correlation_ablation()
    plot_ml_vs_secureshield()
    plot_architecture()
    print(f"Visuals saved to {OUTPUT_DIR}")
