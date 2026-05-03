# =============================================================================
# DeepSentinel — config.py  (UNIFIED — Email + File Monitoring)
# Place this file on BOTH machines (old machine + Dell server)
# =============================================================================

import os

# ─── SERVER SETTINGS ──────────────────────────────────────────────────────────
SERVER_IP   = "192.168.0.107"           # Your Dell machine IP
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5000
SERVER_URL  = f"http://{SERVER_IP}:{SERVER_PORT}/receive_log"

# ─── AGENT IDENTITY ───────────────────────────────────────────────────────────
AGENT_ID = "DESKTOP-OUTLOOK-01"

# ─── FILE MONITORING PATHS (file_agent.py) ───────────────────────────────────
PROJECT_DIR = r'C:\Users\Dell\Desktop\insepticon'
MODEL_DIR   = r'C:\Users\Dell\Desktop\maker\models'
DATA_DIR    = r'C:\Users\Dell\Desktop\maker\data'

MODEL_FILES = {
    'isolation_forest': os.path.join(MODEL_DIR, 'isolation_forest_finetuned.pkl'),
    'autoencoder':      os.path.join(MODEL_DIR, 'autoencoder_finetuned.pth'),
    'scaler':           os.path.join(MODEL_DIR, 'scaler.pkl'),
}

# ─── EMAIL AGENT SETTINGS (run_agent.py) ─────────────────────────────────────
AGENT_POLL_INTERVAL_SECONDS = 30
AGENT_LOOKBACK_MINUTES      = 1440      # 24 hours on first run

# ─── ORGANISATION SETTINGS ────────────────────────────────────────────────────
INTERNAL_DOMAINS = [
    "demoorg.com",
    "sfit.ac.in",
    "yourcompany.com",
]

# ─── DETECTION THRESHOLDS ─────────────────────────────────────────────────────
VOLUME_WINDOW_MINUTES        = 10
VOLUME_SPIKE_THRESHOLD       = 10
ATTACHMENT_SIZE_THRESHOLD_MB = 5
RISKY_ATTACHMENT_EXTENSIONS  = [
    ".exe", ".zip", ".rar", ".7z", ".bat",
    ".sh",  ".ps1", ".msi", ".tar", ".gz",
    ".iso", ".vbs", ".js",  ".sql", ".bak",
]

RISK_KEYWORDS = {
    "critical": [
        "password", "credential", "secret", "private key", "api key",
        "token", "auth", "login details", "access code",
    ],
    "high": [
        "confidential", "top secret", "classified", "do not share",
        "internal only", "proprietary", "trade secret",
    ],
    "medium": [
        "financial data", "client list", "customer data", "salary",
        "acquisition", "merger", "lawsuit", "legal", "nda",
        "termination", "layoff", "budget", "forecast",
    ],
    "low": [
        "project plan", "roadmap", "internal", "draft",
        "not for distribution", "restricted",
    ],
}

# ─── RISK SCORE WEIGHTS ───────────────────────────────────────────────────────
WEIGHT_VOLUME     = 0.20
WEIGHT_KEYWORD    = 0.30
WEIGHT_DOMAIN     = 0.25
WEIGHT_ATTACHMENT = 0.25

RISK_LOW      = 0.30
RISK_MEDIUM   = 0.55
RISK_HIGH     = 0.75
RISK_CRITICAL = 0.90

# ─── PATHS ────────────────────────────────────────────────────────────────────
DB_PATH        = "data/deepsentinel.db"
LOG_PATH       = "logs/sentinel.log"
ALERT_LOG_PATH = "logs/alerts.json"

# ─── DEMO ─────────────────────────────────────────────────────────────────────
DEMO_MODE       = True
DEMO_USER_COUNT = 10
DEMO_ORG_DOMAIN = "demoorg.com"

# ─── SECURITY ─────────────────────────────────────────────────────────────────
API_SECRET_KEY = "deepsentinel-demo-key-change-in-prod"

# ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
def check_files():
    print("🔍 Checking configuration...")
    print(f"   Server URL : {SERVER_URL}")
    print(f"   Agent ID   : {AGENT_ID}")
    if os.path.exists(MODEL_DIR):
        print(f"✅ Model directory found: {MODEL_DIR}")
    else:
        print(f"⚠️  Model directory not found: {MODEL_DIR}")
    for name, path in MODEL_FILES.items():
        print(f"   {'✅' if os.path.exists(path) else '⚠️ NOT FOUND'}  {name}")

if __name__ == "__main__":
    check_files()
