"""SQLite persistence. Raw SQL, no ORM.

Two concerns live here:
  1. The scan-results store (scans, hosts, services, findings).
  2. The NVD CVE cache (cve_cache) — keyed by CVE ID.

All functions take a `sqlite3.Connection` so callers can share transactions.
Use `connect()` for a ready-to-use connection with schema applied.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

from . import config
from .models import CVE, Finding, Host, Scan, ScanStatus, Service, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    completed_at TEXT,
    status      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip       TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);

CREATE TABLE IF NOT EXISTS services (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port       INTEGER NOT NULL,
    protocol   TEXT NOT NULL DEFAULT 'tcp',
    name       TEXT NOT NULL DEFAULT '',
    product    TEXT NOT NULL DEFAULT '',
    version    TEXT NOT NULL DEFAULT '',
    confidence REAL,
    banner     TEXT NOT NULL DEFAULT '',
    cve_ids    TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source         TEXT NOT NULL,
    severity       TEXT NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    remediation    TEXT NOT NULL DEFAULT '',
    host_ip        TEXT NOT NULL,
    port           INTEGER,
    protocol       TEXT NOT NULL DEFAULT 'tcp',
    cve_id         TEXT,
    cvss_v3_score  REAL,
    references_json  TEXT NOT NULL DEFAULT '[]',
    in_kev         INTEGER NOT NULL DEFAULT 0,
    epss_score     REAL,
    exploit_refs_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id         TEXT PRIMARY KEY,
    cvss_v3_score  REAL,
    severity       TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    published_at   TEXT,
    references_json  TEXT NOT NULL DEFAULT '[]',
    fetched_at     TEXT NOT NULL,
    in_kev         INTEGER NOT NULL DEFAULT 0,
    epss_score     REAL,
    exploit_refs_json TEXT NOT NULL DEFAULT '[]'
);
"""


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    """Open a connection with schema applied and foreign keys enforced."""
    path = db_path or config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    _migrate_schema(conn)
    return conn


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Lightweight migrations: add columns that may be missing from older DBs."""
    # CVE cache migrations
    cve_cols = {r[1] for r in conn.execute("PRAGMA table_info(cve_cache)")}
    if "in_kev" not in cve_cols:
        conn.execute(
            "ALTER TABLE cve_cache ADD COLUMN in_kev INTEGER NOT NULL DEFAULT 0"
        )
    if "epss_score" not in cve_cols:
        conn.execute("ALTER TABLE cve_cache ADD COLUMN epss_score REAL")
    if "exploit_refs_json" not in cve_cols:
        conn.execute(
            "ALTER TABLE cve_cache ADD COLUMN exploit_refs_json TEXT NOT NULL DEFAULT '[]'"
        )
    # findings migrations
    finding_cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    if "in_kev" not in finding_cols:
        conn.execute(
            "ALTER TABLE findings ADD COLUMN in_kev INTEGER NOT NULL DEFAULT 0"
        )
    if "epss_score" not in finding_cols:
        conn.execute("ALTER TABLE findings ADD COLUMN epss_score REAL")
    if "exploit_refs_json" not in finding_cols:
        conn.execute(
            "ALTER TABLE findings ADD COLUMN exploit_refs_json TEXT NOT NULL DEFAULT '[]'"
        )


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ---------- scan lifecycle ----------


def insert_scan(conn: sqlite3.Connection, scan: Scan) -> None:
    conn.execute(
        "INSERT INTO scans (id, target, started_at, completed_at, status) VALUES (?, ?, ?, ?, ?)",
        (
            scan.id,
            scan.target,
            scan.started_at.isoformat(),
            scan.completed_at.isoformat() if scan.completed_at else None,
            scan.status.value,
        ),
    )


def update_scan_status(
    conn: sqlite3.Connection,
    scan_id: str,
    status: ScanStatus,
    completed_at: datetime | None = None,
) -> None:
    conn.execute(
        "UPDATE scans SET status = ?, completed_at = ? WHERE id = ?",
        (status.value, completed_at.isoformat() if completed_at else None, scan_id),
    )


def insert_hosts(conn: sqlite3.Connection, scan_id: str, hosts: Iterable[Host]) -> None:
    for host in hosts:
        cur = conn.execute(
            "INSERT INTO hosts (scan_id, ip, hostname) VALUES (?, ?, ?)",
            (scan_id, host.ip, host.hostname),
        )
        host_id = cur.lastrowid
        for svc in host.services:
            conn.execute(
                """INSERT INTO services
                   (host_id, port, protocol, name, product, version, confidence, banner, cve_ids)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    host_id,
                    svc.port,
                    svc.protocol,
                    svc.name,
                    svc.product,
                    svc.version,
                    svc.confidence,
                    svc.banner,
                    json.dumps(svc.cve_ids),
                ),
            )


def insert_findings(
    conn: sqlite3.Connection, scan_id: str, findings: Iterable[Finding]
) -> None:
    conn.executemany(
        """INSERT INTO findings
           (scan_id, source, severity, title, description, remediation,
            host_ip, port, protocol, cve_id, cvss_v3_score, references_json,
            in_kev, epss_score, exploit_refs_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                scan_id,
                f.source.value,
                f.severity.value,
                f.title,
                f.description,
                f.remediation,
                f.host_ip,
                f.port,
                f.protocol,
                f.cve_id,
                f.cvss_v3_score,
                json.dumps(f.references),
                int(f.in_kev),
                f.epss_score,
                json.dumps(f.exploit_refs),
            )
            for f in findings
        ],
    )


# ---------- scan reads ----------


def get_scan(conn: sqlite3.Connection, scan_id: str) -> Scan | None:
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    hosts = _load_hosts(conn, scan_id)
    findings = _load_findings(conn, scan_id)
    return Scan(
        id=row["id"],
        target=row["target"],
        started_at=datetime.fromisoformat(row["started_at"]),
        completed_at=(
            datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
        ),
        status=ScanStatus(row["status"]),
        hosts=hosts,
        findings=findings,
    )


def list_scans(conn: sqlite3.Connection, limit: int = 50) -> list[Scan]:
    rows = conn.execute(
        "SELECT id FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [s for s in (get_scan(conn, r["id"]) for r in rows) if s is not None]


def _load_hosts(conn: sqlite3.Connection, scan_id: str) -> list[Host]:
    host_rows = conn.execute(
        "SELECT id, ip, hostname FROM hosts WHERE scan_id = ? ORDER BY id", (scan_id,)
    ).fetchall()
    hosts: list[Host] = []
    for h in host_rows:
        svc_rows = conn.execute(
            "SELECT * FROM services WHERE host_id = ? ORDER BY port", (h["id"],)
        ).fetchall()
        services = [
            Service(
                port=s["port"],
                protocol=s["protocol"],
                name=s["name"],
                product=s["product"],
                version=s["version"],
                confidence=s["confidence"],
                banner=s["banner"],
                cve_ids=json.loads(s["cve_ids"] or "[]"),
            )
            for s in svc_rows
        ]
        hosts.append(Host(ip=h["ip"], hostname=h["hostname"], services=services))
    return hosts


def _load_findings(conn: sqlite3.Connection, scan_id: str) -> list[Finding]:
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, host_ip, port",
        (scan_id,),
    ).fetchall()
    return [
        Finding(
            source=r["source"],
            severity=Severity(r["severity"]),
            title=r["title"],
            description=r["description"],
            remediation=r["remediation"],
            host_ip=r["host_ip"],
            port=r["port"],
            protocol=r["protocol"],
            cve_id=r["cve_id"],
            cvss_v3_score=r["cvss_v3_score"],
            references=json.loads(r["references_json"] or "[]"),
            in_kev=bool(r["in_kev"]),
            epss_score=r["epss_score"],
            exploit_refs=json.loads(r["exploit_refs_json"] or "[]"),
        )
        for r in rows
    ]


# ---------- CVE cache ----------


def get_cached_cve(conn: sqlite3.Connection, cve_id: str) -> CVE | None:
    """Return a cached CVE if fresh (within TTL). Stale entries are ignored
    so the caller re-fetches and overwrites."""
    row = conn.execute("SELECT * FROM cve_cache WHERE cve_id = ?", (cve_id,)).fetchone()
    if row is None:
        return None
    fetched_at = datetime.fromisoformat(row["fetched_at"])
    if datetime.now(timezone.utc) - fetched_at > timedelta(
        days=config.NVD_CACHE_TTL_DAYS
    ):
        return None
    return CVE(
        id=row["cve_id"],
        cvss_v3_score=row["cvss_v3_score"],
        severity=Severity(row["severity"]),
        description=row["description"],
        published_at=(
            datetime.fromisoformat(row["published_at"]) if row["published_at"] else None
        ),
        references=json.loads(row["references_json"] or "[]"),
        fetched_at=fetched_at,
        in_kev=bool(row["in_kev"]),
        epss_score=row["epss_score"],
        exploit_refs=json.loads(row["exploit_refs_json"] or "[]"),
    )


def put_cve(conn: sqlite3.Connection, cve: CVE) -> None:
    conn.execute(
        """INSERT INTO cve_cache
           (cve_id, cvss_v3_score, severity, description, published_at, references_json, fetched_at,
            in_kev, epss_score, exploit_refs_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(cve_id) DO UPDATE SET
               cvss_v3_score = excluded.cvss_v3_score,
               severity = excluded.severity,
               description = excluded.description,
               published_at = excluded.published_at,
               references_json = excluded.references_json,
               fetched_at = excluded.fetched_at,
               in_kev = excluded.in_kev,
               epss_score = excluded.epss_score,
               exploit_refs_json = excluded.exploit_refs_json""",
        (
            cve.id,
            cve.cvss_v3_score,
            cve.severity.value,
            cve.description,
            cve.published_at.isoformat() if cve.published_at else None,
            json.dumps(cve.references),
            cve.fetched_at.isoformat(),
            int(cve.in_kev),
            cve.epss_score,
            json.dumps(cve.exploit_refs),
        ),
    )


def cache_stats(conn: sqlite3.Connection) -> dict[str, int]:
    total = conn.execute("SELECT COUNT(*) AS n FROM cve_cache").fetchone()["n"]
    return {"cve_cache_entries": total}
