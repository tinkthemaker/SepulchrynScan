"""Tests for CLI subcommands: scan --offline, diff, etc."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


from sepulchrynscan import config, db
from sepulchrynscan.cli import main
from sepulchrynscan.models import (
    Finding,
    FindingSource,
    Scan,
    ScanStatus,
    Severity,
)


def _make_conn():
    return db.connect(db_path=Path(":memory:"))


class TestScanOffline:
    @patch("sepulchrynscan.cli.discovery.run")
    @patch("sepulchrynscan.cli.checks.run_all")
    @patch("sepulchrynscan.cli.cve.enrich")
    @patch("sepulchrynscan.cli.load_allowlist")
    def test_offline_flag_passed_to_enrich(
        self, mock_allowlist, mock_enrich, mock_checks, mock_discovery
    ):
        mock_allowlist.return_value = ["127.0.0.1"]
        mock_discovery.return_value = []
        mock_checks.return_value = []
        mock_enrich.return_value = []

        exit_code = main(["scan", "--offline", "127.0.0.1"])
        assert exit_code == 0
        assert mock_enrich.call_args.kwargs.get("offline") is True

    @patch("sepulchrynscan.cli.discovery.run")
    @patch("sepulchrynscan.cli.checks.run_all")
    @patch("sepulchrynscan.cli.cve.enrich")
    @patch("sepulchrynscan.cli.load_allowlist")
    def test_offline_env_var_passed_to_enrich(
        self, mock_allowlist, mock_enrich, mock_checks, mock_discovery, monkeypatch
    ):
        monkeypatch.setenv(config.OFFLINE_ENV, "1")
        mock_allowlist.return_value = ["127.0.0.1"]
        mock_discovery.return_value = []
        mock_checks.return_value = []
        mock_enrich.return_value = []

        exit_code = main(["scan", "127.0.0.1"])
        assert exit_code == 0
        assert mock_enrich.call_args.kwargs.get("offline") is True


class TestDiffCommand:
    def test_diff_renders_report(self, tmp_path: Path):
        conn = _make_conn()
        scan_a = Scan(
            id="scan-a",
            target="10.0.0.0/24",
            started_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    source=FindingSource.CVE,
                    severity=Severity.HIGH,
                    title="CVE-OLD",
                    host_ip="10.0.0.1",
                    cve_id="CVE-OLD",
                )
            ],
        )
        scan_b = Scan(
            id="scan-b",
            target="10.0.0.0/24",
            started_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    source=FindingSource.CVE,
                    severity=Severity.HIGH,
                    title="CVE-NEW",
                    host_ip="10.0.0.1",
                    cve_id="CVE-NEW",
                )
            ],
        )
        with db.transaction(conn):
            db.insert_scan(conn, scan_a)
            db.insert_scan(conn, scan_b)

        with patch("sepulchrynscan.cli.db.connect", return_value=conn):
            with patch.object(config, "REPORTS_DIR", tmp_path):
                exit_code = main(["diff", "scan-a", "scan-b"])

        assert exit_code == 0
        assert (tmp_path / "diff-scan-a-scan-b" / "diff.html").exists()

    def test_diff_exits_2_when_scan_missing(self):
        exit_code = main(["diff", "missing-a", "missing-b"])
        assert exit_code == 2
