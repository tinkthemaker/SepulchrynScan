# SepulchrynScan

> *"Technical depth meets executive clarity."*

**SepulchrynScan** is a modular, AI-assisted vulnerability scanner built as a portfolio project for cybersecurity job demos. It discovers network services, enriches them with authoritative CVE scoring, runs security configuration checks, and produces **dual-output HTML reports** — a technical deep-dive for practitioners and an executive summary for leadership.

---

## Features

- **Automated Discovery** — Nmap-based port and service detection with the `vulners` NSE script.
- **CVE Enrichment** — Two-stage pipeline: vulners finds CVE IDs, then the NVD API 2.0 supplies authoritative CVSS v3.1 scores. Results are cached in SQLite with TTL.
- **Custom Checks** — HTTP security headers, TLS version & certificate expiry, and exposed-service flagging.
- **Risk Scoring** — Weighted formula (Critical=4×, High=2×, Medium=1×, Low=0.5×) capped at 100.
- **Dual Reports** —
  - **Technical**: sortable/filterable findings table, per-host service details, raw JSON export.
  - **Executive**: risk-score gauge, severity breakdown chart, top-risk-hosts bar chart, print-to-PDF friendly.
- **Allowlist Gate** — Every scan target must be explicitly authorized in `targets.allowlist`.
- **Docker Demo** — One-command OWASP Juice Shop setup for reproducible showcases.

---

## Quick Start

### Prerequisites

- Python 3.10+
- [Nmap](https://nmap.org/download.html) on your PATH
- (Optional) [Docker](https://docs.docker.com/get-docker/) for the Juice Shop demo

### Install

```bash
git clone <repo-url>
cd SepulchrynScan
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run a Scan

Add your target to `targets.allowlist` (one entry per line — IP, CIDR, or hostname):

```text
127.0.0.1
localhost
```

Then scan:

```bash
python -m sepulchrynscan.cli scan 127.0.0.1
```

### Generate Reports

```bash
python -m sepulchrynscan.cli report <scan_id>
```

Outputs two files:
- `reports/<scan_id>/technical.html`
- `reports/<scan_id>/executive.html`

### List Scans

```bash
python -m sepulchrynscan.cli list
```

---

## Docker Demo (OWASP Juice Shop)

A one-command demo target for interviews and portfolio showcases:

```bash
python -m sepulchrynscan.cli demo
```

This will:
1. Start Juice Shop in Docker (`docker compose -f docker/docker-compose.demo.yml up -d`)
2. Wait for the target to respond on `http://localhost:3000`
3. Run a scan against `127.0.0.1`
4. Render both reports
5. Print the report paths

Open the executive report in a browser and use **Print → Save as PDF** for a board-ready artifact.

---

## Architecture

```
sepulchrynscan/
├── models.py      # Pydantic v2 contracts (the inter-module spine)
├── cli.py         # argparse entrypoint + allowlist enforcement
├── discovery.py   # Nmap -sV + vulners → Host / Service models
├── cve.py         # NVD API 2.0 lookup + SQLite cache
├── checks.py      # HTTP headers, TLS config, exposed services
├── risk.py        # Pure risk-score functions
├── report.py      # Jinja2 + Plotly → dual HTML reports
├── db.py          # Raw SQLite (no ORM), schema + CRUD + cache
└── templates/
    ├── technical.html
    └── executive.html
```

Design principles (from the project spec):
- **Pydantic as the contract** — every module consumes and emits typed models.
- **Raw SQL in one file** — `db.py` is readable end-to-end; no ORM.
- **Flat package layout** — ~10 files, each <250 lines, easy to regenerate.
- **HTML-first reporting** — Plotly JSON embedded via CDN; no native PDF dependencies.

---

## Testing

```bash
pytest -v
```

**74 tests** covering risk formulas, CVE cache behavior, NVD API fallback, discovery parsing, allowlist enforcement, report generation, and SQLite round-trips.

```bash
black .
ruff check --fix .
```

---

## Security & Legal Notice

**Use Only on Authorized Targets.** SepulchrynScan includes an allowlist gate (`targets.allowlist`) to prevent accidental scanning of unauthorized systems. By using this tool, you confirm that you have explicit permission to scan every target you add to the allowlist. The authors assume no liability for misuse.

---

## Roadmap (Deferred)

- REST API + Web UI (v1.1)
- Scheduled / recurring scans (v1.1)
- Delta reporting (v1.1)
- Compliance control mapping (v1.2)
- Report branding / custom templates (v1.2)

---

## License

MIT — see [LICENSE](LICENSE) if provided, otherwise treat as unlicensed portfolio code.
