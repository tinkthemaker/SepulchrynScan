# SepulchrynScan — Installation Guide

Complete install instructions for Windows, macOS, and Linux. Each step has a verification command so you can confirm it worked before moving on.

**Estimated time:** 10 minutes (15 if installing Docker).

---

## What you'll install

| Component | Required for | Notes |
|-----------|--------------|-------|
| Python 3.10+ | everything | 3.11 or 3.12 recommended |
| Nmap | any real scan | must be on PATH |
| Git | cloning the repo | skip if downloading as ZIP |
| Docker Desktop | `sepulchryn demo` only | skip if you won't run the Juice Shop demo |
| NVD API key | faster CVE lookups | optional but strongly recommended |

---

## 1. Python 3.10 or newer

### Verify what you already have
```bash
python --version
```
If it prints `Python 3.10.x` or higher, skip to step 2.

### Windows
Install via [python.org](https://www.python.org/downloads/) or winget:
```powershell
winget install Python.Python.3.12
```
**Important:** During the installer, check **"Add python.exe to PATH"**.

### macOS
```bash
brew install python@3.12
```

### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install python3.12 python3.12-venv
```

### Verify
```bash
python --version     # or: python3 --version
```
Expect: `Python 3.10.x` or higher.

---

## 2. Nmap

Every real scan shells out to `nmap`, so the binary must be on your PATH. The `python-nmap` pip package is only a wrapper — it does not include the scanner.

### Windows
```powershell
winget install Insecure.Nmap
```
Or install manually from [nmap.org/download.html](https://nmap.org/download.html) (pick the latest `.exe` installer).

**Important:** Close and reopen your terminal after install so the updated PATH takes effect.

### macOS
```bash
brew install nmap
```

### Linux (Debian/Ubuntu)
```bash
sudo apt install nmap
```

### Verify
```bash
nmap --version
```
Expect a version line like `Nmap version 7.94 (...)`. If the shell reports "command not found," PATH didn't update — open a new terminal, or on Windows add `C:\Program Files (x86)\Nmap` to PATH manually.

### Update the vulners script DB (one-time, recommended)
The `vulners` NSE script ships with Nmap but its CVE database grows stale. Refresh it once:
```bash
nmap --script-updatedb
```
On Windows, run this from an **Administrator** terminal.

---

## 3. Clone the repository

```bash
git clone <repo-url> SepulchrynScan
cd SepulchrynScan
```

Or download the ZIP from GitHub, extract it, and `cd` into the extracted folder.

### Verify
```bash
ls
```
You should see `PROJECT_SPEC.md`, `requirements.txt`, `sepulchrynscan/`, `tests/`, `targets.allowlist`.

---

## 4. Create and activate a virtual environment

A venv isolates SepulchrynScan's dependencies from your system Python.

### Create it
```bash
python -m venv .venv
```

### Activate it

| Shell | Command |
|-------|---------|
| **Windows PowerShell** | `.venv\Scripts\Activate.ps1` |
| **Windows cmd.exe** | `.venv\Scripts\activate.bat` |
| **Windows Git Bash** | `source .venv/Scripts/activate` |
| **macOS / Linux** | `source .venv/bin/activate` |

Your prompt should now show `(.venv)` at the front.

### Verify
```bash
which python     # macOS / Linux / Git Bash
where python     # Windows cmd / PowerShell
```
The path should point inside `.venv/`, not your system Python.

---

## 5. Install Python dependencies

```bash
pip install -r requirements.txt
```

This pulls: `pydantic`, `python-nmap`, `requests`, `cryptography`, `jinja2`, `plotly`, plus dev tools `pytest`, `requests-mock`, `black`, `ruff`.

### Verify
```bash
python -c "import pydantic, nmap, requests, jinja2, plotly; print('ok')"
```
Expect: `ok`.

### Troubleshooting
- **`cryptography` build error on Linux:** install `build-essential libssl-dev libffi-dev python3-dev`, then rerun `pip install`.
- **SSL errors fetching packages:** your corporate proxy may be in the way. Set `HTTP_PROXY` / `HTTPS_PROXY` env vars or use `pip install --cert <path>`.

---

## 6. Run the test suite

```bash
pytest
```
Expect: `92 passed`. If anything fails here, do not proceed — something in the install is wrong.

---

## 7. (Optional) NVD API key

Without a key, the NVD API rate-limits you to **5 requests per 30 seconds**. With a free key you get **50 per 30 seconds**, which matters the first time you scan a host with many services.

1. Request one at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key). They email it within minutes.
2. Set the env var before running scans:

| Shell | Command |
|-------|---------|
| **Windows PowerShell** | `$env:NVD_API_KEY = "your-key-here"` |
| **Windows cmd.exe** | `set NVD_API_KEY=your-key-here` |
| **Windows Git Bash / macOS / Linux** | `export NVD_API_KEY=your-key-here` |

To make it permanent, add the export line to your shell profile (`.bashrc`, `.zshrc`, or PowerShell `$PROFILE`).

### Verify
```bash
python -c "import os; print('key set' if os.environ.get('NVD_API_KEY') else 'no key')"
```

---

## 8. (Optional) Docker — for the Juice Shop demo

Only needed if you plan to run `sepulchryn demo`. Skip this section otherwise.

### Windows / macOS
Install [Docker Desktop](https://docs.docker.com/desktop/). On Windows, Docker Desktop requires WSL 2; the installer handles this.

### Linux
Follow the [official Docker Engine install](https://docs.docker.com/engine/install/).

### Verify
```bash
docker --version
docker compose version
docker run --rm hello-world
```
The `hello-world` container should print a success message.

---

## 9. Smoke test

Everything should now work end-to-end against localhost.

```bash
# targets.allowlist already includes 127.0.0.1
python -m sepulchrynscan.cli scan 127.0.0.1
python -m sepulchrynscan.cli list
python -m sepulchrynscan.cli report <scan_id_from_list>
```

Open `reports/<scan_id>/executive.html` in a browser. You should see a risk-score gauge, severity chart, and (on most workstations) an almost-empty findings table — your laptop is probably firewalled, so zero findings is correct.

### Demo against Juice Shop (if Docker is installed)
```bash
python -m sepulchrynscan.cli demo
```
> **Known issue:** the demo scans `127.0.0.1` with `--top-ports 1000`, but Juice Shop listens on port 3000 (not in the top 1000). Until this is fixed in `cli.py`, the demo will complete successfully but find nothing interesting. See `HANDOFF.md` for the fix.

---

## Full verification checklist

Run these in order. If any fail, fix before moving on.

```bash
python --version                # 3.10+
nmap --version                  # any recent version
git --version                   # any
docker --version                # optional
source .venv/bin/activate       # or Windows equivalent
which python                    # should be inside .venv
pytest                          # 92 passed
python -m sepulchrynscan.cli list   # "no scans recorded" or a list
```

If every command above succeeds, you're done. Move to [README.md](README.md) for day-to-day usage.

---

## Common problems

| Symptom | Cause | Fix |
|---------|-------|-----|
| `nmap: command not found` after install | PATH not refreshed | Reopen terminal; on Windows, add `C:\Program Files (x86)\Nmap` to PATH manually |
| `ModuleNotFoundError: No module named 'sepulchrynscan'` | venv not activated, or running from wrong directory | Activate venv; `cd` to repo root; re-run with `python -m sepulchrynscan.cli ...` |
| `nmap.PortScannerError: 'requires root privileges'` | Some Nmap scans need admin | Run shell as Administrator (Windows) or use `sudo` (macOS/Linux) — or stick to `-sT` connect scans by editing `config.NMAP_ARGS` |
| NVD requests return 403 / 429 | Rate-limited without an API key | Set `NVD_API_KEY` (step 7) |
| `docker: command not found` when running `demo` | Docker not installed or not running | Install Docker Desktop (step 8); make sure the Docker whale icon is active in the system tray |
| Reports are blank or show `NotImplementedError` | Stale build, old scan record | Rerun `scan` then `report`; delete `data/sepulchryn.db` for a clean slate |

---

*End of installation guide.*
