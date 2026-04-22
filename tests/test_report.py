"""Tests for sepulchrynscan/report.py.

Verifies that both HTML files are produced and contain expected content.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


from sepulchrynscan.models import (
    Finding,
    FindingSource,
    Host,
    Scan,
    ScanStatus,
    Service,
    Severity,
)
from sepulchrynscan.report import render


def _sample_scan() -> Scan:
    host = Host(
        ip="10.0.0.1",
        hostname="testhost",
        services=[
            Service(port=80, name="http", product="nginx", version="1.18"),
            Service(port=443, name="https", product="nginx", version="1.18"),
        ],
    )
    findings = [
        Finding(
            source=FindingSource.CVE,
            severity=Severity.CRITICAL,
            title="CVE-2021-44228",
            description="Log4j RCE",
            host_ip="10.0.0.1",
            port=80,
            cve_id="CVE-2021-44228",
            cvss_v3_score=10.0,
        ),
        Finding(
            source=FindingSource.HTTP_HEADERS,
            severity=Severity.MEDIUM,
            title="Missing HSTS",
            description="No HSTS header",
            host_ip="10.0.0.1",
            port=443,
        ),
        Finding(
            source=FindingSource.TLS,
            severity=Severity.HIGH,
            title="Expired certificate",
            description="Cert expired",
            host_ip="10.0.0.1",
            port=443,
        ),
    ]
    return Scan(
        id="abc123",
        target="10.0.0.0/24",
        started_at=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
        status=ScanStatus.COMPLETED,
        hosts=[host],
        findings=findings,
    )


class TestRender:
    def test_creates_both_files(self, tmp_path: Path):
        scan = _sample_scan()
        tech, exec_ = render(scan, tmp_path)
        assert tech.exists()
        assert exec_.exists()
        assert tech.name == "technical.html"
        assert exec_.name == "executive.html"

    def test_technical_contains_findings_table(self, tmp_path: Path):
        scan = _sample_scan()
        tech, _ = render(scan, tmp_path)
        html = tech.read_text(encoding="utf-8")
        assert "CVE-2021-44228" in html
        assert "Missing HSTS" in html
        assert "Expired certificate" in html
        assert "10.0.0.1" in html

    def test_technical_contains_host_details(self, tmp_path: Path):
        scan = _sample_scan()
        tech, _ = render(scan, tmp_path)
        html = tech.read_text(encoding="utf-8")
        assert "testhost" in html
        assert "nginx" in html
        assert "80" in html
        assert "443" in html

    def test_technical_embeds_json(self, tmp_path: Path):
        scan = _sample_scan()
        tech, _ = render(scan, tmp_path)
        html = tech.read_text(encoding="utf-8")
        assert 'id="scan-json"' in html
        assert "abc123" in html

    def test_executive_contains_summary_stats(self, tmp_path: Path):
        scan = _sample_scan()
        _, exec_ = render(scan, tmp_path)
        html = exec_.read_text(encoding="utf-8")
        assert "Executive Summary" in html
        assert "abc123" in html
        assert "10.0.0.0/24" in html

    def test_executive_contains_plotly_charts(self, tmp_path: Path):
        scan = _sample_scan()
        _, exec_ = render(scan, tmp_path)
        html = exec_.read_text(encoding="utf-8")
        assert "cdn.plot.ly" in html
        assert "risk-gauge" in html
        assert "severity-bar" in html
        assert "top-hosts-bar" in html
        assert "Plotly.newPlot" in html

    def test_executive_severity_grid(self, tmp_path: Path):
        scan = _sample_scan()
        _, exec_ = render(scan, tmp_path)
        html = exec_.read_text(encoding="utf-8")
        assert "severity-critical" in html
        assert "severity-high" in html
        assert "severity-medium" in html

    def test_technical_contains_exploit_column(self, tmp_path: Path):
        scan = _sample_scan()
        tech, _ = render(scan, tmp_path)
        html = tech.read_text(encoding="utf-8")
        assert "Exploits" in html

    def test_empty_scan_has_correct_colspan(self, tmp_path: Path):
        scan = Scan(
            id="empty456",
            target="127.0.0.1",
            started_at=datetime.now(timezone.utc),
            status=ScanStatus.COMPLETED,
        )
        tech, _ = render(scan, tmp_path)
        html = tech.read_text(encoding="utf-8")
        assert 'colspan="9"' in html

    def test_executive_contains_exploit_stat(self, tmp_path: Path):
        scan = _sample_scan()
        _, exec_ = render(scan, tmp_path)
        html = exec_.read_text(encoding="utf-8")
        assert "Public Exploits Available" in html

    def test_empty_scan_renders_without_error(self, tmp_path: Path):
        scan = Scan(
            id="empty456",
            target="127.0.0.1",
            started_at=datetime.now(timezone.utc),
            status=ScanStatus.COMPLETED,
        )
        tech, exec_ = render(scan, tmp_path)
        assert tech.exists()
        assert exec_.exists()
        assert "No findings" in tech.read_text(encoding="utf-8")
