import json
import pandas as pd
import numpy as np
import os
from pathlib import Path

# Load metadata for features
meta_path = "models/preprocessing_metadata.json"
if not os.path.exists(meta_path):
    print("Metadata not found.")
    exit(1)

with open(meta_path, "r") as f:
    meta = json.load(f)

features = meta["selected_features"]
n_samples = 100

data = []
for i in range(n_samples):
    row = {}
    is_malicious = i % 2 == 1
    row["Class"] = 1 if is_malicious else 0
    row["Filename"] = f"sample_{i}.exe"
    row["Category"] = "Trojan" if is_malicious else "Benign"
    
    for feat in features:
        if is_malicious:
            row[feat] = np.random.uniform(10, 100)
        else:
            row[feat] = np.random.uniform(0, 5)
    data.append(row)

df = pd.DataFrame(data)
out_dir = Path("data/raw")
out_dir.mkdir(parents=True, exist_ok=True)
df.to_csv(out_dir / "MalMem2022_Binary_Clean.csv", index=False)
print("Generated synthetic dataset at data/raw/MalMem2022_Binary_Clean.csv")
