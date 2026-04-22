"""Risk score computation. Pure functions, fully unit-testable.

Formula (see PROJECT_SPEC.md §5.4 REQ-RPT-03):
    score = min(100, Σ weight(severity) × cvss)
with weights Critical=4, High=2, Medium=1, Low=0.5, None=0.

CVSS is the authoritative score from NVD; for non-CVE findings where no
CVSS is available, a notional value is assigned by severity.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from . import config
from .models import Finding, Severity

_SEVERITY_NOTIONAL_CVSS = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.5,
    Severity.NONE: 0.0,
}


def _finding_weighted_score(finding: Finding) -> float:
    weight = config.SEVERITY_WEIGHTS.get(finding.severity.value, 0.0)
    cvss = finding.cvss_v3_score
    if cvss is None:
        cvss = _SEVERITY_NOTIONAL_CVSS[finding.severity]
    return weight * cvss


def risk_score(findings: Iterable[Finding]) -> float:
    """Return an overall risk score capped at 100."""
    total = sum(_finding_weighted_score(f) for f in findings)
    return round(min(config.RISK_SCORE_CAP, total), 1)


def severity_breakdown(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings per severity. Always returns all severities in priority order."""
    counter: Counter[str] = Counter(f.severity.value for f in findings)
    return {sev.value: counter.get(sev.value, 0) for sev in Severity}


def top_risk_hosts(
    findings: Iterable[Finding], limit: int = 5
) -> list[tuple[str, float]]:
    """Return the highest-scoring hosts by summed weighted score."""
    per_host: dict[str, float] = {}
    for f in findings:
        per_host[f.host_ip] = per_host.get(f.host_ip, 0.0) + _finding_weighted_score(f)
    ranked = sorted(per_host.items(), key=lambda kv: kv[1], reverse=True)
    return [(ip, round(score, 1)) for ip, score in ranked[:limit]]
