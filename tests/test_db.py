"""Tests for sepulchrynscan/db.py.

Covers scan lifecycle, host/service persistence, findings, and CVE cache TTL.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path


from sepulchrynscan import db
from sepulchrynscan.models import (
    CVE,
    Finding,
    FindingSource,
    Host,
    Scan,
    ScanStatus,
    Service,
    Severity,
)


def _make_conn():
    """Return a fresh in-memory SQLite connection with schema applied."""
    return db.connect(db_path=Path(":memory:"))


def _sample_scan(scan_id: str = "scan-001") -> Scan:
    return Scan(
        id=scan_id,
        target="10.0.0.0/24",
        started_at=datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc),
        status=ScanStatus.RUNNING,
    )


class TestConnect:
    def test_applies_schema(self):
        conn = _make_conn()
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = {t["name"] for t in tables}
        assert names >= {"scans", "hosts", "services", "findings", "cve_cache"}

    def test_foreign_keys_enabled(self):
        conn = _make_conn()
        row = conn.execute("PRAGMA foreign_keys").fetchone()
        assert row[0] == 1


class TestTransaction:
    def test_commits_on_success(self):
        conn = _make_conn()
        with db.transaction(conn):
            db.insert_scan(conn, _sample_scan("ok"))
        # After context exits, row is persisted
        row = conn.execute("SELECT id FROM scans WHERE id = ?", ("ok",)).fetchone()
        assert row is not None

    def test_rolls_back_on_exception(self):
        conn = _make_conn()
        try:
            with db.transaction(conn):
                db.insert_scan(conn, _sample_scan("fail"))
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        row = conn.execute("SELECT id FROM scans WHERE id = ?", ("fail",)).fetchone()
        assert row is None


class TestScanLifecycle:
    def test_insert_and_get_round_trip(self):
        conn = _make_conn()
        scan = _sample_scan("s1")
        with db.transaction(conn):
            db.insert_scan(conn, scan)
        fetched = db.get_scan(conn, "s1")
        assert fetched is not None
        assert fetched.id == "s1"
        assert fetched.target == "10.0.0.0/24"
        assert fetched.status == ScanStatus.RUNNING
        assert fetched.hosts == []
        assert fetched.findings == []

    def test_update_scan_status(self):
        conn = _make_conn()
        scan = _sample_scan("s2")
        with db.transaction(conn):
            db.insert_scan(conn, scan)
            db.update_scan_status(
                conn,
                "s2",
                ScanStatus.COMPLETED,
                completed_at=datetime(2024, 6, 1, 12, 5, tzinfo=timezone.utc),
            )
        fetched = db.get_scan(conn, "s2")
        assert fetched is not None
        assert fetched.status == ScanStatus.COMPLETED
        assert fetched.completed_at is not None

    def test_list_scans_ordered_by_started_at_desc(self):
        conn = _make_conn()
        with db.transaction(conn):
            db.insert_scan(
                conn,
                Scan(
                    id="older",
                    target="a",
                    started_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
                ),
            )
            db.insert_scan(
                conn,
                Scan(
                    id="newer",
                    target="b",
                    started_at=datetime(2024, 6, 1, tzinfo=timezone.utc),
                ),
            )
        scans = db.list_scans(conn)
        assert [s.id for s in scans] == ["newer", "older"]


class TestHostsAndServices:
    def test_insert_hosts_with_services(self):
        conn = _make_conn()
        scan = _sample_scan("s3")
        host = Host(
            ip="10.0.0.1",
            hostname="web1",
            services=[
                Service(
                    port=80,
                    protocol="tcp",
                    name="http",
                    product="nginx",
                    version="1.18",
                    confidence=10.0,
                    banner="Server: nginx",
                    cve_ids=["CVE-2021-23017"],
                ),
                Service(port=443, name="https"),
            ],
        )
        with db.transaction(conn):
            db.insert_scan(conn, scan)
            db.insert_hosts(conn, "s3", [host])

        fetched = db.get_scan(conn, "s3")
        assert fetched is not None
        assert len(fetched.hosts) == 1
        assert fetched.hosts[0].ip == "10.0.0.1"
        assert fetched.hosts[0].hostname == "web1"
        assert len(fetched.hosts[0].services) == 2

        svc80 = next(s for s in fetched.hosts[0].services if s.port == 80)
        assert svc80.name == "http"
        assert svc80.product == "nginx"
        assert svc80.version == "1.18"
        assert svc80.confidence == 10.0
        assert svc80.banner == "Server: nginx"
        assert svc80.cve_ids == ["CVE-2021-23017"]

        svc443 = next(s for s in fetched.hosts[0].services if s.port == 443)
        assert svc443.name == "https"

    def test_multiple_hosts(self):
        conn = _make_conn()
        scan = _sample_scan("s4")
        hosts = [
            Host(ip="10.0.0.1", services=[Service(port=22, name="ssh")]),
            Host(ip="10.0.0.2", services=[Service(port=3389, name="ms-wbt-server")]),
        ]
        with db.transaction(conn):
            db.insert_scan(conn, scan)
            db.insert_hosts(conn, "s4", hosts)

        fetched = db.get_scan(conn, "s4")
        assert fetched is not None
        assert len(fetched.hosts) == 2
        ips = {h.ip for h in fetched.hosts}
        assert ips == {"10.0.0.1", "10.0.0.2"}


class TestFindings:
    def test_insert_findings_round_trip(self):
        conn = _make_conn()
        scan = _sample_scan("s5")
        findings = [
            Finding(
                source=FindingSource.CVE,
                severity=Severity.CRITICAL,
                title="CVE-2021-44228",
                description="Log4j",
                remediation="Upgrade",
                host_ip="10.0.0.1",
                port=80,
                protocol="tcp",
                cve_id="CVE-2021-44228",
                cvss_v3_score=10.0,
                references=["https://nvd.nist.gov/"],
            ),
            Finding(
                source=FindingSource.HTTP_HEADERS,
                severity=Severity.MEDIUM,
                title="Missing HSTS",
                host_ip="10.0.0.1",
                port=443,
            ),
        ]
        with db.transaction(conn):
            db.insert_scan(conn, scan)
            db.insert_findings(conn, "s5", findings)

        fetched = db.get_scan(conn, "s5")
        assert fetched is not None
        assert len(fetched.findings) == 2
        titles = {f.title for f in fetched.findings}
        assert titles == {"CVE-2021-44228", "Missing HSTS"}

        cve_finding = next(f for f in fetched.findings if f.cve_id)
        assert cve_finding.cvss_v3_score == 10.0
        assert cve_finding.references == ["https://nvd.nist.gov/"]

    def test_findings_sorted_by_severity(self):
        conn = _make_conn()
        scan = _sample_scan("s6")
        findings = [
            Finding(
                source=FindingSource.CVE,
                severity=Severity.LOW,
                title="Low finding",
                host_ip="10.0.0.1",
            ),
            Finding(
                source=FindingSource.CVE,
                severity=Severity.CRITICAL,
                title="Critical finding",
                host_ip="10.0.0.1",
            ),
        ]
        with db.transaction(conn):
            db.insert_scan(conn, scan)
            db.insert_findings(conn, "s6", findings)

        fetched = db.get_scan(conn, "s6")
        assert fetched is not None
        # Should be ordered by severity (Critical before Low)
        assert fetched.findings[0].severity == Severity.CRITICAL
        assert fetched.findings[1].severity == Severity.LOW


class TestCveCache:
    def test_put_and_get_round_trip(self):
        conn = _make_conn()
        cve = CVE(
            id="CVE-2021-44228",
            cvss_v3_score=9.8,
            severity=Severity.CRITICAL,
            description="Log4j RCE",
            published_at=datetime(2021, 12, 10, tzinfo=timezone.utc),
            references=["https://nvd.nist.gov/"],
            fetched_at=datetime.now(timezone.utc),
        )
        with db.transaction(conn):
            db.put_cve(conn, cve)

        cached = db.get_cached_cve(conn, "CVE-2021-44228")
        assert cached is not None
        assert cached.id == "CVE-2021-44228"
        assert cached.cvss_v3_score == 9.8
        assert cached.severity == Severity.CRITICAL
        assert cached.description == "Log4j RCE"
        assert cached.references == ["https://nvd.nist.gov/"]

    def test_missing_entry_returns_none(self):
        conn = _make_conn()
        assert db.get_cached_cve(conn, "CVE-9999-99999") is None

    def test_stale_entry_returns_none(self, monkeypatch):
        conn = _make_conn()
        now = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(
            "sepulchrynscan.db.datetime",
            type(
                "MockDT",
                (),
                {
                    "now": staticmethod(lambda tz: now),
                    "fromisoformat": datetime.fromisoformat,
                    "timezone": timezone,
                },
            )(),
        )
        # Insert with fetched_at = now - 31 days (stale)
        stale = now - timedelta(days=31)
        cve = CVE(
            id="CVE-2021-44228",
            cvss_v3_score=9.8,
            severity=Severity.CRITICAL,
            fetched_at=stale,
        )
        with db.transaction(conn):
            db.put_cve(conn, cve)

        # When get_cached_cve checks against "now", the entry is stale
        assert db.get_cached_cve(conn, "CVE-2021-44228") is None

    def test_put_overwrites_existing(self):
        conn = _make_conn()
        with db.transaction(conn):
            db.put_cve(
                conn,
                CVE(
                    id="CVE-2021-44228",
                    cvss_v3_score=9.8,
                    severity=Severity.CRITICAL,
                    fetched_at=datetime.now(timezone.utc),
                ),
            )
            db.put_cve(
                conn,
                CVE(
                    id="CVE-2021-44228",
                    cvss_v3_score=10.0,
                    severity=Severity.CRITICAL,
                    description="Updated",
                    fetched_at=datetime.now(timezone.utc),
                ),
            )

        cached = db.get_cached_cve(conn, "CVE-2021-44228")
        assert cached is not None
        assert cached.cvss_v3_score == 10.0
        assert cached.description == "Updated"

    def test_cache_stats(self):
        conn = _make_conn()
        assert db.cache_stats(conn) == {"cve_cache_entries": 0}
        with db.transaction(conn):
            db.put_cve(
                conn,
                CVE(id="CVE-2021-44228", fetched_at=datetime.now(timezone.utc)),
            )
        assert db.cache_stats(conn) == {"cve_cache_entries": 1}


class TestCascadeDelete:
    def test_deleting_scan_cascades_to_hosts_services_findings(self):
        conn = _make_conn()
        scan = _sample_scan("s7")
        host = Host(ip="10.0.0.1", services=[Service(port=80, name="http")])
        finding = Finding(
            source=FindingSource.CVE,
            severity=Severity.HIGH,
            title="X",
            host_ip="10.0.0.1",
        )
        with db.transaction(conn):
            db.insert_scan(conn, scan)
            db.insert_hosts(conn, "s7", [host])
            db.insert_findings(conn, "s7", [finding])

        # Verify everything exists
        assert db.get_scan(conn, "s7") is not None
        assert len(conn.execute("SELECT * FROM hosts").fetchall()) == 1
        assert len(conn.execute("SELECT * FROM services").fetchall()) == 1
        assert len(conn.execute("SELECT * FROM findings").fetchall()) == 1

        # Delete scan
        conn.execute("DELETE FROM scans WHERE id = ?", ("s7",))
        conn.commit()

        # Verify cascade
        assert db.get_scan(conn, "s7") is None
        assert len(conn.execute("SELECT * FROM hosts").fetchall()) == 0
        assert len(conn.execute("SELECT * FROM services").fetchall()) == 0
        assert len(conn.execute("SELECT * FROM findings").fetchall()) == 0
