"""Runtime settings, read once from the environment (and `.env`)."""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = Path(os.getenv("AEGIS_DATA_DIR", ROOT / "data" / "raw"))
RUNS_DIR = Path(os.getenv("AEGIS_RUNS_DIR", ROOT / "data" / "runs"))

MODELS_DIR = Path(os.getenv("AEGIS_MODELS_DIR", ROOT / "data" / "models"))
USERS_FILE = Path(os.getenv("AEGIS_USERS_FILE", ROOT / "data" / "users.json"))
CONTROL_FILE = Path(os.getenv("AEGIS_CONTROL_FILE", ROOT / "data" / "control.json"))
# Analyst-confirmed incidents the family vote learns from.
MEMORY_FILE = Path(os.getenv("AEGIS_MEMORY_FILE", ROOT / "data" / "incident_memory.jsonl"))

# Secrets live outside the run files so whoever can edit a run cannot re-sign it.
SECRETS_DIR = Path(os.getenv("AEGIS_SECRETS_DIR", Path.home() / ".aegis"))
AUDIT_KEY = os.getenv("AEGIS_AUDIT_KEY")  # else generated once in SECRETS_DIR
AUTH_SECRET = os.getenv("AEGIS_AUTH_SECRET")  # else generated once in SECRETS_DIR
# Signed head-of-chain checkpoints, kept apart from the run files.
CHECKPOINT_FILE = Path(os.getenv("AEGIS_CHECKPOINT_FILE", SECRETS_DIR / "audit_checkpoints.jsonl"))
SESSION_HOURS = 12

# Which reasoning model the agents use: "ollama" (local, free, no quota),
# "groq" (hosted free tier) or "gemini".
LLM_PROVIDER = os.getenv("AEGIS_LLM_PROVIDER", "ollama").strip().lower()
LLM_TEMPERATURE = 0.0

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("AEGIS_OLLAMA_MODEL", "qwen2.5:3b")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("AEGIS_GROQ_MODEL", "llama-3.1-8b-instant")

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("AEGIS_MODEL", "gemini-3.5-flash-lite")
GEMINI_TEMPERATURE = LLM_TEMPERATURE

# Monitoring gate: windows scoring at or above this go to the detection agent.
MONITORING_THRESHOLD = 0.6
# Rule-based detector (used when no reasoning model is available): stricter than the gate.
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
