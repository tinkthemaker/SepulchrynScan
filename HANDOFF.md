# SepulchrynScan — Handoff

**For:** next agent/model picking up development
**From:** feature completion session (2026-04-21)
**Read first:** [PROJECT_SPEC.md](PROJECT_SPEC.md) — it is the single source of truth for architecture and scope.

---

## Goal

**SepulchrynScan** is a vibe-coded (AI-generated) vulnerability scanner that produces dual-output reports: a technical HTML for practitioners and an executive HTML for leadership. Portfolio project for cybersecurity job demos. MVP scope is CLI-only.

Key guiding principle: **design decisions favor what AI can generate cleanly.** Flat package tree, Pydantic contracts as the spine, raw SQL, no plugin loaders, no native PDF deps. When in doubt, regenerate a whole file rather than patching.

---

## Current State — MVP is Feature-Complete

All P0 requirements from `PROJECT_SPEC.md` are implemented. Post-MVP additions (KEV/EPSS, offline mode, diff, weak ciphers, admin panels) are also implemented and tested.

### Implemented modules

| File | Status | Notes |
|------|--------|-------|
| `models.py` | Done | Pydantic v2 contracts: `Severity`, `FindingSource`, `ScanStatus`, `CVE`, `Service`, `Host`, `Finding`, `Scan`. `Severity.from_cvss()` is canonical. |
| `db.py` | Done | sqlite3 (no ORM): schema, `connect`, `transaction`, scan CRUD, CVE cache with TTL, lightweight `_migrate_schema()` for new columns. |
| `risk.py` | Done | `risk_score`, `severity_breakdown`, `top_risk_hosts`. Pure functions. Formula locked per spec §5.4. |
| `config.py` | Done | Paths, NVD constants, CISA/EPSS URLs, severity weights, offline env var. |
| `cli.py` | Done | argparse: `scan`, `report`, `demo`, `list`, `diff`. `--offline` flag. Allowlist gate enforced. |
| `discovery.py` | Done | `python-nmap` wrapper. `-sV --top-ports 1000 --script vulners`. Parses CVE IDs via regex. |
| `cve.py` | Done | NVD API 2.0 lookup with 429 backoff, CVSS fallback chain (v3.1 → v3.0 → v2). `offline` param skips uncached CVEs. |
| `kev.py` | Done | **New.** CISA KEV catalog fetch (24h cache) + FIRST.org EPSS batch API. Enriches CVEs in-place. |
| `exploit.py` | Done | **New.** Exploit-DB CSV fetch (7-day cache) + CVE→EDB mapping. Enriches CVEs in-place. |
| `checks.py` | Done | HTTP headers, TLS version/cert expiry/weak ciphers, exposed services, admin panels on non-standard ports. |
| `diff.py` | Done | **New.** `diff_scans()` categorizes findings as new/resolved/persistent by composite key. |
| `report.py` | Done | Jinja2 + Plotly → `technical.html` + `executive.html` + `diff.html`. |
| `templates/` | Done | `technical.html`, `executive.html`, `diff.html`. |
| `docker/` | Done | `Dockerfile` + `docker-compose.demo.yml` with Juice Shop. |

### Test coverage

**101 tests** across:
- `test_risk.py` — risk formula, cap, severity breakdown, host ranking
- `test_cve.py` — NVD fetch, cache hit/miss, 429 backoff, offline mode, exploit hook
- `test_db.py` — schema, transactions, scan lifecycle, hosts/services, findings, CVE cache TTL, cascade delete, exploit_refs round-trip
- `test_discovery.py` — service/CVE extraction, empty results, error handling
- `test_checks.py` — HTTP headers, TLS (version, expiry, weak cipher), exposed services, admin panels
- `test_cli_allowlist.py` — allowlist matching, CLI denial
- `test_cli.py` — offline flag, diff command
- `test_kev.py` — KEV fetch/cache, EPSS batch lookup, CVE enrichment
- `test_exploit.py` — CSV parsing, enrichment, cache TTL, offline mode, graceful failure
- `test_diff.py` — new/resolved/persistent detection
- `test_report.py` — both report files render, Plotly charts present, empty scan OK, exploit column/stat

---

## What Worked

Keep these decisions. They are load-bearing.

- **Pydantic v2 as the inter-module spine.** Every file's inputs and outputs are typed models. Primary defense against AI regeneration drift.
- **Raw SQL in one file.** `db.py` is readable end-to-end. Do not introduce SQLAlchemy or an ORM.
- **Flat package layout.** ~12 files in `sepulchrynscan/`, each under ~300 lines. An agent can rewrite any single file in one turn.
- **HTML-first reporting with Plotly JSON embedded.** Zero native dependencies. Browser print-to-PDF. Do not pull in WeasyPrint or ReportLab.
- **Two-stage CVE pipeline.** Vulners NSE finds CVE IDs (one subprocess, no rate limits). NVD API 2.0 scores them (cached by ID). Risk uses NVD CVSS only.
- **Allowlist gate in `cli.py`.** Enforced via `target_allowed` before any network I/O.
- **Checks are hardcoded functions, no plugin loader.** If a 5th check is needed, add a function and call it from `run_all`.
- **KEV + EPSS enrichment is opt-in by architecture.** It runs automatically during CVE enrichment but degrades gracefully on network failure (warnings, not crashes).

---

## What Didn't Work / Was Rejected

Do not re-introduce these.

- **WeasyPrint for PDF.** GTK dependency hell on Windows. Replaced with HTML + browser print.
- **Plugin architecture for checks.** Premature abstraction. Dynamic loaders make regeneration brittle.
- **FastAPI REST layer and Web UI in MVP.** Too many surfaces. Deferred to v1.1 per spec §13.
- **SQLAlchemy / any ORM.** Obscures SQL and adds cross-file state that AI regeneration breaks.
- **Version-string → NVD lookup as primary CVE source.** Extremely noisy false positives. Vulners NSE uses CPE matching and is far more accurate.
- **Default-credential detection.** Low signal + legal/ethical baggage for a portfolio demo. Deferred indefinitely.

---

## Environment Notes

- **OS:** Windows 11; shell is PowerShell / Git Bash.
- **Python:** 3.11+ (tested on 3.11.9).
- **Nmap binary** must be on PATH for `discovery.py` to work.
- **NVD API key** (optional) raises rate limit from 5/30s to 50/30s. Env var: `NVD_API_KEY`.
- **Offline mode** env var: `SEPULCHRYN_OFFLINE=1` or `--offline` flag.

---

## Next Steps — if you pick this up

### 1. Verify the environment works
```bash
cd /e/SepulchrynScan
.venv\Scripts\pytest -v    # expect 92 passed
.venv\Scripts\python -m sepulchrynscan.cli list   # "no scans recorded" or a list
```

### 2. Likely extension areas

| Area | Why | Complexity |
|------|-----|------------|
| **FastAPI REST layer** | v1.1 roadmap — wraps existing pipeline functions in HTTP endpoints | Medium |
| **Scheduled scans** | v1.1 roadmap — `sepulchryn daemon` with `schedule` lib | Low |
| **SARIF export** | v1.4 roadmap — `sepulchryn export <scan_id> --format sarif` | Low |
| **Report branding** | v1.2 roadmap — custom logo, company name, disclaimer via config | Low |
| **Webhook alerts** | v1.3 roadmap — POST to Slack/Teams when critical findings found | Low |
| **NIST 800-53 / CIS mapping** | v1.3 roadmap — map findings to compliance controls | High |
| **Cloud provider checks** | v1.5 roadmap — S3/Blob exposure scanning | High |

### 3. If you add a feature

1. Update `models.py` if you change data shapes — **all consumers must be updated in the same commit.**
2. Update `db.py` schema + CRUD if you add fields. Use `_migrate_schema()` pattern for backward compatibility.
3. Add pytest coverage for anything involving money, security, or caching behavior.
4. Run `black .` and `ruff check --fix .` before finishing.
5. Update `README.md` and `PROJECT_SPEC.md` if user-facing behavior changes.

---

## Contributor Rules (from spec §14)

1. Regenerate, don't patch, if a file has drifted.
2. Pydantic is the contract. Never break `models.py` shapes without updating every consumer.
3. One file, one concern. No cross-module side effects.
4. Raw SQL stays raw.
5. No plugin systems, no dynamic loaders.
6. Security-first. Detect only. No hardcoded credentials. No `shell=True`.
7. Respect the allowlist — any network-bound code path goes through `target_allowed`.
8. Test `risk`, `cve` cache, allowlist, and offline mode. UI polish is not a testing priority.
9. Format before commit: `black .` and `ruff check --fix .`.

---

*End of handoff.*
