
import argparse
import os
import subprocess
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

parser = argparse.ArgumentParser(description="AI-NIDS PCAP Attack Detection")

parser.add_argument("--pcap", required=True)
parser.add_argument("--cfm", required=True)
parser.add_argument("--model", required=True)
parser.add_argument("--encoder", required=True)
parser.add_argument("--mapping", required=True)
parser.add_argument("--output", required=True)

args = parser.parse_args()

pcap_path = Path(args.pcap).resolve()
cfm_path = Path(args.cfm).resolve()
output_dir = Path(args.output).resolve()

output_dir.mkdir(parents=True, exist_ok=True)

# Validate input files
for path in [pcap_path, cfm_path, Path(args.model),
             Path(args.encoder), Path(args.mapping)]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

# Run CICFlowMeter
env = os.environ.copy()
native_path = cfm_path.parent.parent / "lib" / "native"
env["LD_LIBRARY_PATH"] = str(native_path) + ":" + env.get("LD_LIBRARY_PATH", "")

result = subprocess.run(
    [str(cfm_path), str(pcap_path), str(output_dir)],
    capture_output=True,
    text=True,
    env=env,
    cwd=str(cfm_path.parent)
)

if result.returncode != 0:
    raise RuntimeError(result.stderr or "CICFlowMeter extraction failed")

# Locate extracted flow CSV
csv_files = list(output_dir.glob("*_Flow.csv"))

if not csv_files:
    raise FileNotFoundError("CICFlowMeter flow CSV was not generated")

flow_csv = max(csv_files, key=lambda p: p.stat().st_mtime)
flow_df = pd.read_csv(flow_csv)

# Load feature mapping
mapping_df = pd.read_csv(args.mapping)
training_features = mapping_df["Training Feature"].tolist()
source_features = mapping_df["CICFlowMeter Feature"].tolist()

# Align features in training order
aligned = flow_df[source_features].copy()
aligned.columns = training_features

# Clean invalid rows
aligned = aligned.replace([np.inf, -np.inf], np.nan)
valid_indices = aligned.dropna().index
aligned = aligned.loc[valid_indices].copy()

if aligned.empty:
    raise ValueError("No valid flows available for prediction")

# Load trained model and label encoder
model = joblib.load(args.model)
encoder = joblib.load(args.encoder)

# Generate predictions
encoded_predictions = model.predict(aligned)
predictions = encoder.inverse_transform(encoded_predictions.astype(int))
probabilities = model.predict_proba(aligned)

# Create prediction results
results = pd.DataFrame({
    "Flow_ID": flow_df.loc[valid_indices, "Flow ID"].values,
    "Predicted_Label": predictions,
    "Confidence": (probabilities.max(axis=1) * 100).round(2)
})

# Save predictions
prediction_path = output_dir / (pcap_path.name + "_Predictions.csv")
results.to_csv(prediction_path, index=False)

print("AI-NIDS inference completed successfully!")
print("Total valid flows:", len(results))
print("Prediction summary:")
print(results["Predicted_Label"].value_counts())
print("Prediction file:", prediction_path)
