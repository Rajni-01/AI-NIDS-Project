import argparse
import os
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description="Extract network flow features using CICFlowMeter")
parser.add_argument("--cfm-path", required=True, help="Path to CICFlowMeter executable")
parser.add_argument("--input-pcap", required=True, help="Path to input PCAP file")
parser.add_argument("--output-dir", required=True, help="Directory for extracted CSV files")
args = parser.parse_args()

cfm_path = Path(args.cfm_path).resolve()
input_pcap = Path(args.input_pcap).resolve()
output_dir = Path(args.output_dir).resolve()

if not cfm_path.exists():
    raise FileNotFoundError(f"CICFlowMeter executable not found: {cfm_path}")

if not input_pcap.exists():
    raise FileNotFoundError(f"PCAP file not found: {input_pcap}")

output_dir.mkdir(parents=True, exist_ok=True)

env = os.environ.copy()
native_path = cfm_path.parent.parent / "lib" / "native"
env["LD_LIBRARY_PATH"] = str(native_path) + ":" + env.get("LD_LIBRARY_PATH", "")

result = subprocess.run(
    [str(cfm_path), str(input_pcap), str(output_dir)],
    capture_output=True,
    text=True,
    env=env,
    cwd=str(cfm_path.parent)
)

print(result.stdout)
if result.stderr:
    print(result.stderr)

if result.returncode != 0:
    raise RuntimeError(f"CICFlowMeter failed with exit code {result.returncode}")

print("Feature extraction completed successfully.")
print("Output directory:", output_dir)
