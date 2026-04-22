# SepulchrynScan — Project Specification
## Automated Vulnerability Scanner with Executive Reporting

**Version:** 2.0.0
**Status:** MVP Development
**Last Updated:** 2026-04-21
**Author:** Project Lead
**Purpose:** Single source of truth for all agents, models, and contributors.

---

## 1. Project Identity

| Attribute | Value |
|-----------|-------|
| **Codename** | SepulchrynScan |
| **Tagline** | *"Technical depth meets executive clarity."* |
| **Category** | Cybersecurity / Vulnerability Management |
| **Target Audience** | Security teams, CISOs, compliance officers, hiring managers |
| **Demo Context** | Portfolio project for cybersecurity employment |
| **Development Mode** | AI-assisted ("vibe coded") — design decisions favor AI-generatable code |

SepulchrynScan is a modular, automated vulnerability scanner that discovers network services, enriches findings with authoritative CVE data, and generates dual-output reports: a **technical deep-dive** for security practitioners and an **executive summary** for leadership decision-making.

---

## 2. Core Objectives

### 2.1 Primary Objectives

1. **Automated Discovery** — Scan target hosts to identify open ports, running services, and version information with minimal configuration.
2. **Vulnerability Enrichment** — Use Nmap's `vulners` NSE script to identify CVE IDs per service, then query the NVD API for authoritative CVSS v3.1 scoring.
3. **Dual-Report Generation** — Produce two reports from a single scan:
   - **Technical Report**: sortable HTML table of findings, CVSS breakdowns, affected hosts/ports, remediation references.
   - **Executive Report**: standalone HTML with risk score, attack-surface chart, priority matrix. Browser print → PDF if needed.
4. **Operational Efficiency** — Cache NVD responses in SQLite; respect rate limits.

### 2.2 Deferred (See §13 Roadmap)

REST API, web UI, scheduling, delta scanning, plugin architecture, compliance mapping, report branding, default-credential detection.

---

## 3. Problem Statement

> Existing vulnerability scanners fall into two extremes: they either overwhelm non-technical stakeholders with raw data, or they are prohibitively expensive enterprise platforms. SepulchrynScan bridges this gap by delivering automated technical depth alongside executive-ready risk communication — because security programs only succeed when decision-makers understand and act on risk.

### 3.1 Pain Points Addressed

| Pain Point | SepulchrynScan Solution |
|------------|------------------------|
| Raw scan data is unreadable to leadership | Executive HTML report with risk score + charts |
| Commercial scanners are costly | Open-source stack, free NVD API |
| Manual CVE lookup is slow | `vulners` discovery + NVD scoring with caching |
| Hard to demonstrate security value to executives | Business-risk translation via risk score |

---

## 4. Target Users & Use Cases

### 4.1 User Personas

| Persona | Role | Needs |
|---------|------|-------|
| **Alex** | SOC Analyst / Security Engineer | Detailed findings, remediation refs, exportable JSON |
| **Jordan** | CISO / Security Manager | Risk overview, board-ready visuals |
| **Casey** | Compliance Officer | (v1.2+) Control mapping for audit evidence |
| **You** | Job Candidate | Demo story of engineering + stakeholder communication |

### 4.2 MVP Use Cases

- **UC-01:** Run a one-off scan against a single host and generate both reports.
- **UC-02:** Scan the bundled OWASP Juice Shop demo target end-to-end as a reproducible showcase.
- **UC-03:** Open the executive HTML, print to PDF, hand to leadership.

Deferred: scheduled recurring scans (v1.1), delta reporting (v1.1), REST integration (v1.1), custom check plugins (v1.2).

---

## 5. Functional Requirements (MVP)

### 5.1 Discovery (REQ-DIS)

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-DIS-01 | Accept single IP, CIDR, hostname, or URL as target input. | P0 |
| REQ-DIS-02 | Perform TCP port scanning (top 1000 ports) with service/version detection (`-sV`). | P0 |
| REQ-DIS-03 | Produce Pydantic-typed `Host` → `Service` structures from Nmap XML output. | P0 |
| REQ-DIS-04 | Refuse any target not present in `targets.allowlist`. | P0 |

### 5.2 Vulnerability Enrichment (REQ-CVE)

Two-stage pipeline, explicit separation of concerns:

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-CVE-01 | **Stage 1 (discovery):** Run Nmap `vulners` NSE script to obtain CVE IDs per service. | P0 |
| REQ-CVE-02 | **Stage 2 (scoring):** For each CVE ID, check SQLite cache; on miss, query NVD API 2.0 for CVSS v3.1 base score, severity, description, references. Persist to cache. | P0 |
| REQ-CVE-03 | Risk score is computed from **NVD-sourced** CVSS, not vulners' potentially stale data. | P0 |
| REQ-CVE-04 | Support offline mode: use cached NVD data only; skip uncached CVEs with a warning. | P1 |
| REQ-CVE-05 | NVD cache schema includes `fetched_at` timestamp; entries older than 30 days are refreshed opportunistically. | P1 |
| REQ-CVE-06 | Enrich CVEs with Exploit-DB references via local CSV lookup. | P1 |

### 5.3 Custom Checks (REQ-CHK)

Three hardcoded checks in a single `checks.py` file. No plugin loader.

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-CHK-01 | HTTP security headers check (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy). | P0 |
| REQ-CHK-02 | SSL/TLS configuration check (protocol version, cert validity, weak ciphers). | P0 |
| REQ-CHK-03 | Exposed-service heuristic (flag common admin panels on non-standard ports). | P1 |

### 5.4 Reporting (REQ-RPT)

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-RPT-01 | Technical HTML report: sortable/filterable findings table, CVE references, embedded JSON export. | P0 |
| REQ-RPT-02 | Executive HTML report: standalone file with embedded Plotly charts (risk score gauge, severity breakdown, top-risk hosts). | P0 |
| REQ-RPT-03 | Risk score formula, capped 0–100: `min(100, Σ weight(severity) × cvss)` with weights **Critical=4, High=2, Medium=1, Low=0.5, None=0**. Implemented as a single pure function. | P0 |
| REQ-RPT-04 | Both reports render from the same Pydantic models via Jinja2. | P0 |

### 5.5 Interface (REQ-CLI)

CLI only for MVP. Subcommands:

| Command | Purpose |
|---------|---------|
| `sepulchryn scan <target>` | Discovery + enrichment + checks → writes findings to SQLite |
| `sepulchryn report <scan_id>` | Renders technical + executive HTML from stored findings |
| `sepulchryn demo` | Starts Juice Shop via docker-compose, scans it, generates reports |
| `sepulchryn list` | Lists recent scans with IDs and timestamps |

---

## 6. Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| **Performance** | Single-host scan + reports in under 2 minutes end-to-end. |
| **Scalability** | Handle up to 254 hosts (/24 subnet) per scan. |
| **Reliability** | Gracefully handle unreachable hosts, NVD timeouts, malformed output. |
| **Security** | Detect only — never exploit. Refuse targets not in allowlist. |
| **Privacy** | All data stored locally; zero telemetry. |
| **Maintainability** | PEP 8; `black` + `ruff`; Pydantic models as the inter-module contract; docstrings on public functions only. |
| **Portability** | Linux, macOS, Windows (Nmap binary required). Docker image for zero-setup demos. |

---

## 7. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                          CLI (argparse)                      │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     SCAN PIPELINE (orchestrator)             │
└──┬──────────────────┬──────────────────┬────────────────────┘
   │                  │                  │
   ▼                  ▼                  ▼
┌──────────┐    ┌─────────────┐    ┌──────────────┐
│ discovery│    │ cve         │    │ checks       │
│ (nmap -sV│───▶│ stage 1:    │    │ (http_hdrs,  │
│  +vulners│    │  vulners IDs│    │  tls, expose)│
│  NSE)    │    │ stage 2:    │    │              │
│          │    │  NVD→SQLite │    │              │
└──────────┘    └─────────────┘    └──────────────┘
       │               │                  │
       └───────────────┼──────────────────┘
                       ▼
             ┌─────────────────────┐
             │  SQLite findings DB │
             │  (scans, hosts,     │
             │   findings, cve_cache)│
             └──────────┬──────────┘
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
     ┌───────────────┐     ┌───────────────┐
     │ technical.html│     │ executive.html│
     │ (Jinja2)      │     │ (Jinja2 +     │
     │               │     │  Plotly JSON) │
     └───────────────┘     └───────────────┘
```

### 7.1 Data Flow

1. CLI validates target against `targets.allowlist`.
2. `discovery.run()` → Nmap `-sV --script vulners` → Pydantic `list[Host]` with services and raw CVE IDs.
3. `cve.enrich()` → for each CVE ID: SQLite cache lookup, fall back to NVD API → authoritative `CVE` records.
4. `checks.run_all()` → HTTP headers, TLS, exposed services → additional `Finding` records.
5. All results persisted to SQLite with a `scan_id`.
6. `report.render(scan_id)` → two HTML files in `reports/<scan_id>/`.

---

## 8. Technology Stack

Selected for deep AI training-data coverage and zero native-dependency pain.

| Layer | Technology | Why this choice for AI-assisted dev |
|-------|-----------|-------------------------------------|
| **Language** | Python 3.10+ | Highest-quality AI code generation |
| **Data contracts** | Pydantic v2 | AI writes Pydantic fluently; explicit types catch regeneration drift |
| **Port/Service scanning** | `python-nmap` + `nmap` binary | Structured XML output, AI-friendly parsing |
| **CVE discovery** | Nmap `vulners` NSE script | One subprocess call, structured output, no rate limits |
| **CVE scoring** | NVD API 2.0 (REST) via `requests` | Authoritative CVSS source |
| **HTTP/TLS checks** | `requests`, stdlib `ssl`, `cryptography` | Canonical libraries with extensive AI training data |
| **Persistence** | stdlib `sqlite3` (raw SQL, no ORM) | AI writes SQL better than it wires SQLAlchemy relationships |
| **CLI** | stdlib `argparse` | Zero deps, sufficient for MVP |
| **Templating** | Jinja2 | De facto standard |
| **Charts** | Plotly (embedded JSON → HTML) | Self-contained HTML output, no PDF/native deps |
| **PDF** | *(none)* | Browser print from executive HTML when needed |
| **Containerization** | Docker + docker-compose | `docker-compose.demo.yml` bundles Juice Shop target |
| **Formatting/Lint** | `black`, `ruff` | Fast, opinionated, AI-regeneration-safe |

### 8.1 Deliberate non-choices

- **WeasyPrint** — rejected. GTK dependency hell on Windows; unnecessary given HTML-first reporting.
- **SQLAlchemy/ORM** — rejected. Raw SQL is clearer for AI and for a SQLite-scale schema.
- **FastAPI / Web UI** — deferred to v1.1. Fewer surfaces = fewer files AI must keep coherent.
- **Plugin loader for checks** — rejected. Three functions in one file is faster to regenerate than a dynamic loader.

---

## 9. Directory Structure

Deliberately flat. Each file is small enough for an AI to fully rewrite in one turn.

```
SepulchrynScan/
├── sepulchrynscan/
│   ├── __init__.py
│   ├── cli.py              # argparse entrypoint, command dispatch
│   ├── config.py           # paths, constants, NVD rate limits
│   ├── models.py           # Pydantic: Scan, Host, Service, Finding, CVE
│   ├── db.py               # sqlite3, raw SQL, schema + helpers
│   ├── discovery.py        # python-nmap + vulners NSE → list[Host]
│   ├── cve.py              # NVD API client + SQLite cache
│   ├── checks.py           # http_headers(), tls_config(), exposed_services()
│   ├── risk.py             # risk_score() pure function
│   ├── report.py           # Jinja2 render, Plotly chart JSON
│   └── templates/
│       ├── technical.html
│       └── executive.html
├── tests/                  # pytest
├── reports/                # generated <scan_id>/technical.html + executive.html
├── data/                   # sepulchryn.db
├── docker/
│   ├── Dockerfile
│   └── docker-compose.demo.yml   # scanner + Juice Shop
├── targets.allowlist        # authorization gate
├── requirements.txt
├── README.md
└── PROJECT_SPEC.md
```

---

## 10. Key Design Decisions

### 10.1 CVE pipeline: vulners for discovery, NVD for scoring
`vulners` NSE returns CVE IDs (and sometimes stale CVSS) directly from Nmap output — one subprocess call, no rate limits. We discard vulners' CVSS and query NVD API 2.0 per CVE ID for authoritative CVSS v3.1. Because we're querying by ID (not version string), cache hit rate is high and rate-limit pressure is minimal.

### 10.2 HTML-first reporting (no native PDF lib)
The executive report is a self-contained HTML file with embedded Plotly chart JSON. This sidesteps WeasyPrint/GTK install pain, survives regeneration cleanly (HTML+CSS+JSON is AI's strongest output), and browser-print-to-PDF remains trivially available.

### 10.3 Pydantic as the inter-module spine
Every module consumes and emits Pydantic models. This is the single most effective safeguard against AI regeneration drift: type errors surface immediately when a regenerated module's shape disagrees with its neighbors.

### 10.4 Flat structure, raw SQL, no plugin loader
Deep package trees and dynamic loaders cost AI context. A flat module tree with ~10 files — each under ~200 lines — lets an AI regenerate any single file without loading the whole project. Raw SQL is more robust under regeneration than ORM relationship graphs.

### 10.5 CLI-only MVP
A single entrypoint means a single contract for AI to maintain. FastAPI and Web UI (v1.1) can reuse the same pipeline functions when added.

### 10.6 Dual-report philosophy retained
The executive/technical split is the project's actual differentiator and stays P0. Cutting it would make this "just another scanner."

### 10.7 Exploit-availability signal
Exploit-DB CSV lookup adds a third enrichment pillar alongside KEV and EPSS. It answers "is there a public exploit?" without crossing the detect-only line. Metadata only; no active exploitation.

---

## 11. Risk & Constraints

| Risk | Mitigation |
|------|------------|
| NVD API rate limits (5 req/30s unauth, 50 with key) | Cache by CVE ID; only uncached IDs are fetched; backoff on 429 |
| Nmap `vulners` script may be out of date locally | Dockerfile pins Nmap version; README documents `nmap --script-updatedb` |
| False positives in service version detection | Display confidence level in report; surface the raw Nmap banner |
| Legal/ethical scanning concerns | `targets.allowlist` enforced in CLI; README includes responsible-use block |
| AI regeneration drift between modules | Pydantic contracts + pytest on `risk_score` and CVE-cache behavior |

---

## 12. Success Criteria

- [x] `sepulchryn demo` spins up Juice Shop, scans it, and writes two HTML reports in under 2 minutes.
- [x] Technical report contains NVD-authoritative CVSS scores and working reference links.
- [x] Executive report contains a risk-score gauge, severity breakdown chart, and a top-risk-hosts chart.
- [x] Scanner refuses a target not in `targets.allowlist`.
- [x] Rescanning the same target hits the CVE cache with >90% hit rate (observed in logs).
- [x] Docker demo (`docker-compose -f docker/docker-compose.demo.yml up`) succeeds on a clean machine.
- [x] `pytest` passes with coverage on `risk.py`, `cve.py`, `db.py`.

### Post-MVP Additions (Implemented)

- [x] `--offline` flag skips NVD API calls; uses cache only (REQ-CVE-04).
- [x] Weak cipher detection in TLS check (REQ-CHK-02).
- [x] Admin-panel heuristic on non-standard ports (REQ-CHK-03).
- [x] CISA KEV + EPSS enrichment on CVE findings.
- [x] Exploit-DB enrichment on CVE findings.
- [x] `sepulchryn diff` delta reporting between two scans.

---

## 13. Future Roadmap

| Phase | Feature | Rationale for deferral |
|-------|---------|------------------------|
| **v1.1** | FastAPI REST layer over existing pipeline | Second interface, same pipeline |
| **v1.1** | ~~Delta scanning + trend visualization~~ | **Done in v1.0** — `sepulchryn diff` |
| **v1.1** | Scheduled recurring scans | Wraps `sepulchryn scan` in `schedule` lib |
| **v1.2** | Custom check plugin loader | Only worth it once a 4th check is actually needed |
| **v1.2** | Web UI (FastAPI + HTMX or minimal React) | After REST layer exists |
| **v1.3** | NIST 800-53 / CIS Controls v8 mapping | Needs stable finding taxonomy first |
| **v1.3** | Webhook alerts (Slack/Teams) | Needs severity thresholds defined |
| **v1.4** | SARIF export for CI/CD | Standardized output format |
| **v1.5** | Cloud provider checks (S3/Blob exposure) | Separate discovery pipeline |

---

## 14. Agent / Model Instructions

This project is intentionally vibe-coded. When contributing:

1. **Regenerate, don't patch.** If a file has drifted, rewrite it whole against this spec rather than applying surgical edits.
2. **Pydantic is the contract.** Never break `models.py` shapes without updating every consumer in the same change.
3. **One file, one concern.** Do not add cross-module side effects. `discovery.py` produces Hosts; `cve.py` enriches them; `report.py` renders them.
4. **Raw SQL stays raw.** Do not introduce SQLAlchemy or other ORMs.
5. **No plugin systems, no dynamic loaders.** If a 4th check is needed, add a 4th function to `checks.py` and call it from the pipeline.
6. **Security-first.** Detect only. No hardcoded credentials. No shell=True. No unvalidated input to subprocess.
7. **Respect the allowlist.** Any code path that reaches out to a network target must go through the `targets.allowlist` check.
8. **Test what matters.** `risk_score`, CVE cache behavior, and allowlist enforcement require pytest coverage. UI polish does not.
9. **Format before commit.** `black .` and `ruff check --fix .`.

---

## 15. Glossary

| Term | Definition |
|------|------------|
| **CVE** | Common Vulnerabilities and Exposures — standardized identifier for known security flaws. |
| **CVSS** | Common Vulnerability Scoring System — numerical severity score (0.0–10.0). |
| **NVD** | National Vulnerability Database — U.S. government CVE repository; authoritative CVSS source in this project. |
| **NSE** | Nmap Scripting Engine — Lua scripts extending Nmap. |
| **vulners** | NSE script that maps detected service versions to CVE IDs. |
| **Delta Scan** | (v1.1) Comparison between scan runs to identify new or resolved findings. |
| **SARIF** | (v1.4) Static Analysis Results Interchange Format. |
| **Vibe coding** | AI-assisted development mode; design decisions favor fully regeneratable, AI-friendly code. |

---

*End of Specification*
