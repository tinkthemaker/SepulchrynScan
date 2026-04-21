# SepulchrynScan — Handoff

**For:** next agent/model picking up development
**From:** initial scaffolding session (2026-04-21)
**Read first:** [PROJECT_SPEC.md](PROJECT_SPEC.md) — it is the single source of truth for architecture and scope.

---

## Goal

Build **SepulchrynScan**, a vibe-coded (AI-generated) vulnerability scanner that produces dual-output reports: a technical HTML for practitioners and an executive HTML for leadership. Portfolio project for cybersecurity job demos. MVP scope is CLI-only; see `PROJECT_SPEC.md §13` for what is deferred.

Key guiding principle: **design decisions favor what AI can generate cleanly.** Flat package tree, Pydantic contracts as the spine, raw SQL, no plugin loaders, no native PDF deps. When in doubt, regenerate a whole file rather than patching.

---

## Current Progress

### Fully implemented
- [sepulchrynscan/models.py](sepulchrynscan/models.py) — Pydantic v2 contracts: `Severity`, `FindingSource`, `ScanStatus`, `CVE`, `Service`, `Host`, `Finding`, `Scan`. `Severity.from_cvss()` is the canonical CVSS→bucket mapping.
- [sepulchrynscan/db.py](sepulchrynscan/db.py) — sqlite3 (no ORM): schema, `connect`, `transaction`, scan CRUD, CVE cache with TTL.
- [sepulchrynscan/risk.py](sepulchrynscan/risk.py) — `risk_score`, `severity_breakdown`, `top_risk_hosts`. Pure functions. Formula is locked in per spec §5.4 REQ-RPT-03.
- [sepulchrynscan/config.py](sepulchrynscan/config.py) — paths, NVD constants, severity weights.
- [sepulchrynscan/cli.py](sepulchrynscan/cli.py) — argparse with `scan`, `report`, `demo`, `list`. Allowlist gate (`target_allowed`) is enforced in `_cmd_scan`. `list` works end-to-end.
- [tests/test_risk.py](tests/test_risk.py) — 8 tests covering the risk formula, severity breakdown, host ranking.
- [targets.allowlist](targets.allowlist), [.gitignore](.gitignore), [requirements.txt](requirements.txt).

### Stubbed (signatures + `TODO(vibe)` notes only)
- [sepulchrynscan/discovery.py](sepulchrynscan/discovery.py) — `run(target) -> list[Host]`
- [sepulchrynscan/cve.py](sepulchrynscan/cve.py) — `enrich(conn, hosts) -> list[Finding]`, `fetch_cve_from_nvd(cve_id)`
- [sepulchrynscan/checks.py](sepulchrynscan/checks.py) — `http_headers`, `tls_config`, `exposed_services`, `run_all`
- [sepulchrynscan/report.py](sepulchrynscan/report.py) — `render(scan, out_dir) -> (tech_path, exec_path)`
- [sepulchrynscan/templates/technical.html](sepulchrynscan/templates/technical.html) and [executive.html](sepulchrynscan/templates/executive.html) — placeholder bodies with TODO blocks describing required context vars and output.

### Not yet written
- `docker/Dockerfile` and `docker/docker-compose.demo.yml` (demo target: OWASP Juice Shop).
- `README.md`.
- Unit tests for `db.py`, `cve.py`, and allowlist enforcement.
- Any scan has ever actually run — the pipeline is not yet wired.

---

## What Worked

Keep these decisions. They are load-bearing and were made deliberately.

- **Pydantic v2 as the inter-module spine.** Every file's inputs and outputs are typed models. This is the primary defense against AI regeneration drift.
- **Raw SQL in one file.** `db.py` is readable end-to-end. Do not introduce SQLAlchemy or another ORM — regeneration becomes fragile.
- **Flat package layout.** ~10 files in `sepulchrynscan/`, each under ~250 lines. An agent can rewrite any single file in one turn without needing the whole project in context.
- **HTML-first reporting with Plotly JSON embedded.** Zero native dependencies. Browser print-to-PDF if a PDF is wanted. **Do not** pull in WeasyPrint, ReportLab, or anything that requires GTK/Cairo/binary wheels.
- **Two-stage CVE pipeline.** Vulners NSE finds CVE IDs in discovery (one subprocess call, no rate limits). NVD API 2.0 scores them (cached by ID, high hit rate). Risk score uses the NVD-sourced CVSS only — vulners' CVSS is ignored as potentially stale.
- **Allowlist gate in `cli.py`.** Enforce via `target_allowed` before any network I/O. Any new code path that reaches a target must honor it.
- **Three checks hardcoded in `checks.py`, no plugin loader.** If a 4th is ever needed, add a 4th function and call it from `run_all`.

---

## What Didn't Work / Was Rejected

Do not re-introduce these without a very strong reason. Each was considered and cut.

- **WeasyPrint for PDF generation.** GTK dependency chain on Windows is install hell and fragile across Docker base images. Replaced with HTML + browser print.
- **Plugin architecture for custom checks.** Premature abstraction for three checks. Dynamic loaders make regeneration brittle.
- **FastAPI REST layer and Web UI in MVP.** Too many surfaces for an AI to keep coherent simultaneously. Deferred to v1.1 per spec §13.
- **SQLAlchemy / any ORM.** Obscures the SQL and adds cross-file state that AI regeneration breaks easily.
- **Version-string → NVD lookup as primary CVE source.** Extremely noisy (false positives dominate). Vulners NSE does the matching better because it uses CPE.
- **Default-credential detection in MVP.** Low signal + legal/ethical baggage for a portfolio demo. Deferred indefinitely.
- **Scheduling, delta scans, compliance mapping, report branding in MVP.** Already in the roadmap (§13). Do not pull them forward.
- **Name "SentinelScan".** Earlier draft name. Current name is **SepulchrynScan**. If you see "Sentinel" anywhere outside git history, it is a bug.

---

## Environment Notes

- **OS:** Windows 11; shell is Git Bash (Unix syntax, forward-slash paths).
- **Python:** 3.10+. No venv has been created yet — do that first (`python -m venv .venv`).
- **Pyright is loud:** editor will show "Import ... could not be resolved" for every intra-package import until a venv is created and the editor points at it. These are false alarms, not bugs.
- **Nmap binary** must be on PATH for `discovery.py` to work. Docker image will pin it.
- **NVD API key** (optional) raises rate limit from 5/30s to 50/30s. Env var: `NVD_API_KEY`.

---

## Next Steps — in priority order

### 1. Bootstrap the environment (5 min)
```bash
cd /e/SepulchrynScan
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
.venv/Scripts/pytest    # should show 8 passing in tests/test_risk.py
.venv/Scripts/python -m sepulchrynscan.cli list   # should print "no scans recorded"
```
If `pytest` passes and `cli list` runs clean, the contracts compile and the DB schema applies. That is the green light for building outward.

### 2. Implement `cve.py` (highest leverage, no external binary needed)
File: [sepulchrynscan/cve.py](sepulchrynscan/cve.py)

- `fetch_cve_from_nvd(cve_id)`:
  - `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>` (constant in `config.NVD_API_URL`).
  - Honor `NVD_API_KEY` env var via header `apiKey`.
  - Sleep `config.NVD_RATE_LIMIT_SLEEP_SEC` between calls; exponential backoff on HTTP 429.
  - Extract CVSS from `vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore`, fall back to `cvssMetricV30`, then `cvssMetricV2`.
  - Pull `descriptions[?lang=en].value`, `published`, and `references[*].url`.
  - Return a `CVE` model. `Severity.from_cvss()` derives the bucket.

- `enrich(conn, hosts)`:
  - Collect all unique CVE IDs from every `Service.cve_ids` across `hosts`.
  - For each: `db.get_cached_cve()` → fall back to `fetch_cve_from_nvd()` → `db.put_cve()`.
  - Emit one `Finding` per (service, CVE) with `source=FindingSource.CVE`, `host_ip`, `port`, `protocol`, `cve_id`, `cvss_v3_score`, `severity`, references copied from the CVE.

- Add `tests/test_cve.py` with requests-mock covering cache hit / cache miss / 429 backoff / missing-CVSS fallback.

### 3. Implement `discovery.py`
File: [sepulchrynscan/discovery.py](sepulchrynscan/discovery.py)

- Use `python-nmap`'s `PortScanner`.
- Arguments from `config.NMAP_ARGS` (currently `-sV --top-ports 1000 --script vulners`).
- For each host in scan result, build a `Host`; for each port, build a `Service`.
- Parse the vulners output from `port['script']['vulners']` using regex `r'CVE-\d{4}-\d{4,}'`, dedupe into `Service.cve_ids`.
- Handle unreachable host gracefully — return an empty list with a warning, do not crash.

### 4. Wire the pipeline in `cli.py`
File: [sepulchrynscan/cli.py](sepulchrynscan/cli.py) function `_cmd_scan`

```python
hosts = discovery.run(args.target)
with db.connect() as conn, db.transaction(conn):
    db.insert_hosts(conn, scan.id, hosts)
    cve_findings = cve.enrich(conn, hosts)
    check_findings = checks.run_all(hosts)
    db.insert_findings(conn, scan.id, cve_findings + check_findings)
    db.update_scan_status(conn, scan.id, ScanStatus.COMPLETED, completed_at=datetime.now(timezone.utc))
```
At this point `sepulchryn scan 127.0.0.1` should produce a populated SQLite row you can inspect.

### 5. Implement `checks.py`
File: [sepulchrynscan/checks.py](sepulchrynscan/checks.py)

- `http_headers`: requests with 5s timeout. Required headers and their severity on absence: HSTS=Medium, CSP=Medium, X-Frame-Options=Low, X-Content-Type-Options=Low, Referrer-Policy=Low.
- `tls_config`: for every service with name matching `https|ssl|tls`, use `ssl.create_default_context()` + `wrap_socket` and inspect negotiated protocol. Flag TLS < 1.2 as High. Use `cryptography.x509` to parse cert expiry; flag <30 days = Medium, expired = Critical.
- `exposed_services`: static dict of `(port, name) → severity`, e.g. `(23, "telnet") → Critical`, `(3389, "ms-wbt-server") → High`.

### 6. Implement `report.py` + fill templates
File: [sepulchrynscan/report.py](sepulchrynscan/report.py)

- Jinja2 `Environment(loader=FileSystemLoader(config.TEMPLATES_DIR), autoescape=True)`.
- Pass `scan`, `findings`, `risk_score`, `severity_breakdown`, `top_hosts`, and a dict of Plotly figures (each `fig.to_json()`).
- Executive template uses Plotly CDN; technical template uses a sortable JS table (vanilla is fine, no framework).
- Write both files to `config.REPORTS_DIR / scan.id / {technical,executive}.html`.

### 7. Docker demo
Create `docker/docker-compose.demo.yml` with two services: the scanner image and `bkimminich/juice-shop`. Expose Juice Shop on an internal network name `juice-shop` so the allowlist entry matches. `sepulchryn demo` runs `docker compose up -d`, waits for the target to respond, runs `scan` + `report`, prints the output paths.

### 8. Backfill missing tests
- `tests/test_db.py` — insert round-trip for scan/hosts/findings, CVE cache TTL behavior.
- `tests/test_cli_allowlist.py` — `target_allowed` against IPs, CIDRs, hostnames; CLI exits 2 on denial.

---

## Contributor Rules (from spec §14)

1. Regenerate, don't patch, if a file has drifted.
2. Pydantic is the contract. Never break `models.py` shapes without updating every consumer in the same change.
3. One file, one concern. Do not add cross-module side effects.
4. Raw SQL stays raw.
5. No plugin systems, no dynamic loaders.
6. Security-first. Detect only. No hardcoded credentials. No `shell=True`. No unvalidated input to subprocess.
7. Respect the allowlist — any network-bound code path goes through `target_allowed`.
8. Test `risk`, `cve` cache, and allowlist. UI polish is not a testing priority.
9. Format before commit: `black .` and `ruff check --fix .`.

---

*End of handoff.*
