"""Paths and constants. Single source of tunable values."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "reports"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

DB_PATH = DATA_DIR / "sepulchryn.db"
ALLOWLIST_PATH = ROOT / "targets.allowlist"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY_ENV = "NVD_API_KEY"
NVD_RATE_LIMIT_SLEEP_SEC = 6.0
NVD_TIMEOUT_SEC = 15
NVD_CACHE_TTL_DAYS = 30

NMAP_TOP_PORTS = 1000
NMAP_ARGS = f"-sV --top-ports {NMAP_TOP_PORTS} --script vulners"

SEVERITY_WEIGHTS = {
    "Critical": 4.0,
    "High": 2.0,
    "Medium": 1.0,
    "Low": 0.5,
    "None": 0.0,
}

RISK_SCORE_CAP = 100.0


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
