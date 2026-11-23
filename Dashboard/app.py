"""
AI-NIDS Dashboard entry point.
Redirects execution to frontend/app.py.
"""
from pathlib import Path
import runpy

app_path = Path(__file__).resolve().parent.parent / "frontend" / "app.py"
runpy.run_path(str(app_path), run_name="__main__")
