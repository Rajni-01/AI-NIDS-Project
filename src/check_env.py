"""Environment check for the AI-NIDS project.

Run from the project root:  python src/check_env.py
Prints the Python version and the version of every required library.
Take a screenshot of this output as proof that the Week 1 environment works.
"""
import importlib
import sys

# (import name, display name)
LIBRARIES = [
    ("pandas", "pandas"),
    ("numpy", "numpy"),
    ("sklearn", "scikit-learn"),
    ("lightgbm", "lightgbm"),
    ("xgboost", "xgboost"),
    ("imblearn", "imbalanced-learn"),
    ("matplotlib", "matplotlib"),
    ("seaborn", "seaborn"),
    ("plotly", "plotly"),
    ("streamlit", "streamlit"),
    ("shap", "shap"),
    ("scapy", "scapy"),
    ("pyshark", "pyshark"),
    ("jupyter_core", "jupyter"),
]

print(f"Python {sys.version.split()[0]}")
print("-" * 40)

missing = []
for module_name, display in LIBRARIES:
    try:
        module = importlib.import_module(module_name)
        version = getattr(module, "__version__", "installed (no version attribute)")
        print(f"[OK]      {display:<18} {version}")
    except Exception as exc:  # ImportError or a broken install
        print(f"[MISSING] {display:<18} {type(exc).__name__}: {exc}")
        missing.append(display)

print("-" * 40)
if missing:
    print("Problem libraries: " + ", ".join(missing))
    print("Fix them with: pip install <name>, then run this script again.")
else:
    print("All libraries imported successfully. Environment is ready.")