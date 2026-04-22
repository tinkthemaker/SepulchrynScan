"""Tests for sepulchrynscan/diff.py."""

from __future__ import annotations

from datetime import datetime, timezone

from sepulchrynscan.diff import diff_scans
from sepulchrynscan.models import (
    Finding,
    FindingSource,
    Scan,
    ScanStatus,
    Severity,
)


def _sample_finding(title: str, cve_id: str | None = None, port: int = 80) -> Finding:
    return Finding(
        source=FindingSource.CVE,
        severity=Severity.HIGH,
        title=title,
        host_ip="10.0.0.1",
        port=port,
        cve_id=cve_id,
    )


def _sample_scan(scan_id: str, findings: list[Finding]) -> Scan:
    return Scan(
        id=scan_id,
        target="10.0.0.0/24",
        started_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        status=ScanStatus.COMPLETED,
        findings=findings,
    )


class TestDiffScans:
    def test_detects_new_findings(self):
        a = _sample_scan("a", [_sample_finding("OLD", "CVE-OLD")])
        b = _sample_scan(
            "b", [_sample_finding("OLD", "CVE-OLD"), _sample_finding("NEW", "CVE-NEW")]
        )
        result = diff_scans(a, b)
        assert result.new_count == 1
        assert result.new[0].title == "NEW"
        assert result.resolved_count == 0
        assert result.persistent_count == 1

    def test_detects_resolved_findings(self):
        a = _sample_scan("a", [_sample_finding("OLD", "CVE-OLD")])
        b = _sample_scan("b", [])
        result = diff_scans(a, b)
        assert result.new_count == 0
        assert result.resolved_count == 1
        assert result.persistent_count == 0

    def test_empty_both_sides(self):
        a = _sample_scan("a", [])
        b = _sample_scan("b", [])
        result = diff_scans(a, b)
        assert result.new_count == 0
        assert result.resolved_count == 0
        assert result.persistent_count == 0
