"""Runtime settings, read once from the environment (and `.env`)."""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = Path(os.getenv("AEGIS_DATA_DIR", ROOT / "data" / "raw"))
RUNS_DIR = Path(os.getenv("AEGIS_RUNS_DIR", ROOT / "data" / "runs"))

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("AEGIS_MODEL", "gemini-3.5-flash-lite")

# Monitoring gate: windows scoring at or above this go to the detection agent.
MONITORING_THRESHOLD = 0.6
# Rule-based detector (used when Gemini is off): stricter than the gate.
RULES_DETECTION_THRESHOLD = 0.75
# Governance: responses below this detector confidence need an analyst.
AUTO_APPROVE_MIN_CONFIDENCE = 80

CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "AEGIS_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if o.strip()
]
