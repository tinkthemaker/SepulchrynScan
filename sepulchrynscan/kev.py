"""CISA KEV catalog + EPSS scoring enrichment.

Contract:
    enrich_findings(findings, cve_map) -> None  (mutates in-place)

Fetches:
  - CISA Known Exploited Vulnerabilities catalog (cached 24h).
  - FIRST.org EPSS scores (batched API call).
"""

from __future__ import annotations

import json
import warnings
from datetime import datetime, timedelta, timezone

import requests

from . import config
from .models import CVE, Finding


def _kev_cache_path() -> str:
    return str(config.DATA_DIR / "cisa_kev.json")


def _kev_cache_fresh() -> bool:
    path = config.DATA_DIR / "cisa_kev.json"
    if not path.exists():
        return False
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return datetime.now(timezone.utc) - mtime < timedelta(
        hours=config.KEV_CACHE_TTL_HOURS
    )


def load_kev_catalog() -> set[str]:
    """Download CISA KEV JSON if stale; return set of CVE IDs."""
    if _kev_cache_fresh():
        data = json.loads((config.DATA_DIR / "cisa_kev.json").read_text())
        return {v["cveID"] for v in data.get("vulnerabilities", [])}

    try:
        resp = requests.get(config.CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        warnings.warn(f"CISA KEV fetch failed: {exc}")
        return set()

    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    (config.DATA_DIR / "cisa_kev.json").write_text(json.dumps(data))
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Query EPSS API for multiple CVEs. Returns {cve_id: epss_score}."""
    if not cve_ids:
        return {}

    scores: dict[str, float] = {}
    # EPSS handles comma-separated CVEs; chunk conservatively at 100
    for i in range(0, len(cve_ids), 100):
        chunk = cve_ids[i : i + 100]
        try:
            resp = requests.get(
                config.EPSS_API_URL,
                params={"cve": ",".join(chunk)},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("data", []):
                scores[item["cve"]] = float(item.get("epss", 0))
        except Exception as exc:
            warnings.warn(f"EPSS fetch failed for chunk {i}: {exc}")
    return scores


def enrich_cves(cves: list[CVE]) -> None:
    """Mutate CVE objects in-place with KEV and EPSS data."""
    if not cves:
        return

    kev_set = load_kev_catalog()
    epss_scores = fetch_epss_scores([c.id for c in cves])

    for cve in cves:
        cve.in_kev = cve.id in kev_set
        cve.epss_score = epss_scores.get(cve.id)


def enrich_findings(findings: list[Finding]) -> None:
    """Mutate Finding objects in-place with KEV/EPSS from their CVE IDs."""
    if not findings:
        return

    kev_set = load_kev_catalog()
    cve_ids = [f.cve_id for f in findings if f.cve_id]
    epss_scores = fetch_epss_scores(cve_ids)

    for f in findings:
        if f.cve_id:
            f.in_kev = f.cve_id in kev_set
            f.epss_score = epss_scores.get(f.cve_id)
