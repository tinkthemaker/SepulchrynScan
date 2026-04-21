"""Tests for the risk score formula. Per PROJECT_SPEC.md §5.4 REQ-RPT-03,
this function must be pure and unit-testable — that is what lives here."""
from __future__ import annotations

from sepulchrynscan.models import Finding, FindingSource, Severity
from sepulchrynscan.risk import risk_score, severity_breakdown, top_risk_hosts


def _f(severity: Severity, cvss: float | None, host_ip: str = "10.0.0.1") -> Finding:
    return Finding(
        source=FindingSource.CVE,
        severity=severity,
        title="t",
        host_ip=host_ip,
        cvss_v3_score=cvss,
    )


def test_empty_findings_score_is_zero():
    assert risk_score([]) == 0.0


def test_score_is_capped_at_100():
    findings = [_f(Severity.CRITICAL, 10.0) for _ in range(50)]
    assert risk_score(findings) == 100.0


def test_weighted_sum_of_cvss_critical():
    # one critical @ CVSS 9.5, weight 4 → 38.0
    assert risk_score([_f(Severity.CRITICAL, 9.5)]) == 38.0


def test_weighted_sum_mixed_severities():
    # Critical 10.0 * 4 = 40.0; High 7.0 * 2 = 14.0; Medium 5.0 * 1 = 5.0
    findings = [
        _f(Severity.CRITICAL, 10.0),
        _f(Severity.HIGH, 7.0),
        _f(Severity.MEDIUM, 5.0),
    ]
    assert risk_score(findings) == 59.0


def test_none_severity_contributes_zero():
    assert risk_score([_f(Severity.NONE, 0.0)]) == 0.0


def test_finding_without_cvss_uses_notional_value():
    # High notional = 8.0; weight 2 → 16.0
    assert risk_score([_f(Severity.HIGH, None)]) == 16.0


def test_severity_breakdown_returns_all_severities():
    findings = [_f(Severity.HIGH, 7.0), _f(Severity.HIGH, 8.0), _f(Severity.LOW, 2.0)]
    assert severity_breakdown(findings) == {
        "Critical": 0, "High": 2, "Medium": 0, "Low": 1, "None": 0,
    }


def test_top_risk_hosts_ranks_by_weighted_score():
    findings = [
        _f(Severity.CRITICAL, 10.0, host_ip="10.0.0.1"),
        _f(Severity.LOW, 2.0, host_ip="10.0.0.2"),
        _f(Severity.HIGH, 8.0, host_ip="10.0.0.3"),
    ]
    ranked = top_risk_hosts(findings, limit=3)
    assert ranked[0][0] == "10.0.0.1"
    assert ranked[-1][0] == "10.0.0.2"
