"""Command-line entrypoint. argparse, four subcommands.

sepulchryn scan <target>       # discovery + enrichment + checks
sepulchryn report <scan_id>    # render HTML reports for an existing scan
sepulchryn demo                # docker-compose up juice-shop → scan → report
sepulchryn list                # list recent scans
"""

from __future__ import annotations

import argparse
import ipaddress
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

from . import checks, config, cve, db, discovery, report
from .models import Scan, ScanStatus


def _uuid() -> str:
    return uuid.uuid4().hex[:12]


def load_allowlist(path: Path | None = None) -> list[str]:
    p = path or config.ALLOWLIST_PATH
    if not p.exists():
        return []
    return [
        line.strip()
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def target_allowed(target: str, allowlist: list[str]) -> bool:
    """Return True if `target` matches any allowlist entry.

    Matching rules:
      - Exact string match (hostnames, URLs).
      - If entry is a CIDR and target is an IP, check IP ∈ network.
      - If entry is an IP and target is the same IP, match.
    """
    t = target.strip()
    for entry in allowlist:
        if entry == t:
            return True
        try:
            net = ipaddress.ip_network(entry, strict=False)
            try:
                ip = ipaddress.ip_address(t)
                if ip in net:
                    return True
            except ValueError:
                pass
        except ValueError:
            pass
    return False


def _cmd_scan(args: argparse.Namespace, nmap_override: str | None = None) -> int:
    allowlist = load_allowlist()
    if not target_allowed(args.target, allowlist):
        print(
            f"error: target '{args.target}' is not in {config.ALLOWLIST_PATH}. "
            "Add it explicitly — scans on unauthorized targets are refused.",
            file=sys.stderr,
        )
        return 2

    config.ensure_dirs()
    scan = Scan(id=_uuid(), target=args.target, started_at=datetime.now(timezone.utc))

    with db.connect() as conn, db.transaction(conn):
        db.insert_scan(conn, scan)
        hosts = discovery.run(args.target, arguments=nmap_override)
        db.insert_hosts(conn, scan.id, hosts)
        cve_findings = cve.enrich(conn, hosts)
        check_findings = checks.run_all(hosts)
        db.insert_findings(conn, scan.id, cve_findings + check_findings)
        db.update_scan_status(
            conn,
            scan.id,
            ScanStatus.COMPLETED,
            completed_at=datetime.now(timezone.utc),
        )

    print(f"scan {scan.id} completed against {args.target}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    with db.connect() as conn:
        scan = db.get_scan(conn, args.scan_id)
    if scan is None:
        print(f"error: no scan with id {args.scan_id}", file=sys.stderr)
        return 2
    tech_path, exec_path = report.render(scan, config.REPORTS_DIR / scan.id)
    print(f"technical  → {tech_path}")
    print(f"executive  → {exec_path}")
    return 0


def _cmd_demo(_: argparse.Namespace) -> int:
    """Start the Juice Shop demo target, scan it, and render reports."""
    compose_file = (
        Path(__file__).resolve().parent.parent / "docker" / "docker-compose.demo.yml"
    )
    if not compose_file.exists():
        print(f"error: demo compose file not found at {compose_file}", file=sys.stderr)
        return 1

    # Start the demo target (juice-shop only; scanner service is optional)
    print("starting demo target ...")
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "up", "-d", "juice-shop"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"error: failed to start demo target\n{result.stderr}",
            file=sys.stderr,
        )
        return 1

    # Wait for the target to respond
    target_url = "http://127.0.0.1:3000"
    print(f"waiting for {target_url} ...")
    for attempt in range(30):
        try:
            requests.get(target_url, timeout=5)
            print("demo target is ready")
            break
        except Exception:
            time.sleep(2)
    else:
        print("error: demo target did not become ready in time", file=sys.stderr)
        return 1

    # Run scan against localhost, forcing port 3000 because Juice Shop
    # lives outside Nmap's default --top-ports 1000.
    scan_args = argparse.Namespace(target="127.0.0.1")
    rc = _cmd_scan(scan_args, nmap_override="-sV -p 3000 --script vulners")
    if rc != 0:
        return rc

    # Fetch the latest scan ID
    with db.connect() as conn:
        scans = db.list_scans(conn, limit=1)
    if not scans:
        print("error: no scan record found after demo run", file=sys.stderr)
        return 1
    latest_scan_id = scans[0].id

    # Render reports
    report_args = argparse.Namespace(scan_id=latest_scan_id)
    return _cmd_report(report_args)


def _cmd_list(_: argparse.Namespace) -> int:
    with db.connect() as conn:
        scans = db.list_scans(conn)
    if not scans:
        print("no scans recorded")
        return 0
    for s in scans:
        print(
            f"{s.id}  {s.started_at.isoformat(timespec='seconds')}  {s.status.value:>9}  {s.target}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sepulchryn")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run a scan against a target")
    s.add_argument(
        "target", help="IP, CIDR, hostname, or URL (must be in targets.allowlist)"
    )
    s.set_defaults(func=_cmd_scan)

    r = sub.add_parser("report", help="render HTML reports for a prior scan")
    r.add_argument("scan_id")
    r.set_defaults(func=_cmd_report)

    d = sub.add_parser("demo", help="run the bundled Juice Shop demo")
    d.set_defaults(func=_cmd_demo)

    list_parser = sub.add_parser("list", help="list recent scans")
    list_parser.set_defaults(func=_cmd_list)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
