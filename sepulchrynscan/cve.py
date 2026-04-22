"""CVE enrichment stage.

Contract:
    enrich(conn, hosts) -> list[Finding]

Two-stage pipeline (PROJECT_SPEC.md §5.2):
  1. Vulners (already ran in discovery.py) gave us CVE IDs per service.
  2. For each distinct CVE ID: SQLite cache lookup; on miss or stale entry,
     query NVD API 2.0 for authoritative CVSS v3.1 score and metadata.

Risk score uses NVD-sourced CVSS, not vulners' potentially stale scores.
"""

from __future__ import annotations

import os
import sqlite3
import time
import warnings
from datetime import datetime

import requests

from . import config, db, exploit, kev
from .models import CVE, Finding, FindingSource, Host, Severity


def fetch_cve_from_nvd(cve_id: str) -> CVE:
    """Query NVD API 2.0 for a single CVE ID.

    Rate-limiting behaviour:
      - Sleeps ``config.NVD_RATE_LIMIT_SLEEP_SEC`` after every successful call.
      - On HTTP 429 implements exponential backoff and retries up to 3 times.
    """
    headers: dict[str, str] = {}
    api_key = os.environ.get(config.NVD_API_KEY_ENV)
    if api_key:
        headers["apiKey"] = api_key

    params = {"cveId": cve_id}
    max_retries = 3
    response = None

    for attempt in range(max_retries):
        response = requests.get(
            config.NVD_API_URL,
            params=params,
            headers=headers,
            timeout=config.NVD_TIMEOUT_SEC,
        )
        if response.status_code == 429:
            backoff = config.NVD_RATE_LIMIT_SLEEP_SEC * (2**attempt)
            time.sleep(backoff)
            continue
        response.raise_for_status()
        break
    else:
        # All retries exhausted – raise for the last response
        if response is not None:
            response.raise_for_status()
        raise requests.HTTPError("NVD request failed after retries")

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        time.sleep(config.NVD_RATE_LIMIT_SLEEP_SEC)
        return CVE(id=cve_id)

    cve_data = vulnerabilities[0].get("cve", {})
    metrics = cve_data.get("metrics", {})

    # CVSS extraction: prefer v3.1, then v3.0, then v2
    score: float | None = None
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key)
        if metric_list:
            candidate = metric_list[0].get("cvssData", {}).get("baseScore")
            if candidate is not None:
                score = float(candidate)
                break

    # English description
    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Published date
    published_at: datetime | None = None
    published_raw = cve_data.get("published")
    if published_raw:
        published_at = datetime.fromisoformat(published_raw.replace("Z", "+00:00"))

    # References
    references = [
        ref.get("url", "") for ref in cve_data.get("references", []) if ref.get("url")
    ]

    time.sleep(config.NVD_RATE_LIMIT_SLEEP_SEC)
    return CVE(
        id=cve_id,
        cvss_v3_score=score,
        severity=Severity.from_cvss(score),
        description=description,
        published_at=published_at,
        references=references,
    )


def enrich(
    conn: sqlite3.Connection, hosts: list[Host], offline: bool = False
) -> list[Finding]:
    """Turn vulners CVE IDs on each service into scored Findings.

    Args:
        offline: If True, skip NVD API calls for uncached CVEs and emit a
                 warning instead of a Finding.
    """
    # 1. Collect unique CVE IDs
    cve_ids: set[str] = set()
    for host in hosts:
        for svc in host.services:
            cve_ids.update(svc.cve_ids)

    # 2. Resolve each CVE (cache -> NVD -> cache)
    cve_map: dict[str, CVE] = {}
    for cve_id in cve_ids:
        cached = db.get_cached_cve(conn, cve_id)
        if cached is not None:
            cve_map[cve_id] = cached
        elif offline:
            warnings.warn(f"Offline mode: CVE {cve_id} not in cache; skipping.")
        else:
            fetched = fetch_cve_from_nvd(cve_id)
            db.put_cve(conn, fetched)
            cve_map[cve_id] = fetched

    # 3. Enrich with KEV + EPSS
    if cve_map:
        kev.enrich_cves(list(cve_map.values()))
        exploit.enrich_cves(list(cve_map.values()))

    # 4. Emit one Finding per (service, CVE)
    findings: list[Finding] = []
    for host in hosts:
        for svc in host.services:
            for cve_id in svc.cve_ids:
                cve = cve_map.get(cve_id)
                if cve is None:
                    continue
                findings.append(
                    Finding(
                        source=FindingSource.CVE,
                        severity=cve.severity,
                        title=cve_id,
                        description=cve.description,
                        host_ip=host.ip,
                        port=svc.port,
                        protocol=svc.protocol,
                        cve_id=cve_id,
                        cvss_v3_score=cve.cvss_v3_score,
                        references=cve.references,
                        in_kev=cve.in_kev,
                        epss_score=cve.epss_score,
                        exploit_refs=cve.exploit_refs,
                    )
                )
    return findings
