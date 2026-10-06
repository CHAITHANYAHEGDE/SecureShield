import pandas as pd
from secureshield.data.loader import load_raw_dataset

df, _ = load_raw_dataset("data/raw/MalMem2022_Binary_Clean.csv")
print("Total rows:", len(df))
print("Exact duplicates:", df.duplicated().sum())

# Drop labels and leakage columns
X = df.drop(columns=["Class", "Category", "Filename"], errors="ignore")
print("Duplicates excluding labels/categories:", X.duplicated().sum())

# Let's see if there are near-duplicates
# For MalMem2022, many samples might just be memory dumps from the same process
print("Class distribution:", df['Class'].value_counts().to_dict())

# Correlation with target
import numpy as np
y = df["Class"].apply(lambda x: 1 if "Malware" in str(x) else 0)
if y.sum() == 0:
    y = df["Class"]

correlations = {}
for col in X.select_dtypes(include=[np.number]).columns:
    corr = np.corrcoef(X[col].fillna(0), y)[0, 1]
    correlations[col] = corr

# Top 5 correlated features
sorted_corr = sorted(correlations.items(), key=lambda x: abs(x[1] if not np.isnan(x[1]) else 0), reverse=True)
print("Top 5 correlated features:")
for col, corr in sorted_corr[:5]:
    print(f"{col}: {corr:.4f}")
