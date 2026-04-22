"""Scan diff / delta reporting.

Contract:
    diff_scans(scan_a, scan_b) -> DiffResult

Compares two Scan objects and categorizes findings as new, resolved, or
persistent based on a composite key.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Scan


def _finding_key(f: Finding) -> tuple:
    return (f.host_ip, f.port or 0, f.cve_id or "", f.title)


@dataclass
class DiffResult:
    scan_a_id: str
    scan_b_id: str
    new: list[Finding]
    resolved: list[Finding]
    persistent: list[Finding]

    @property
    def new_count(self) -> int:
        return len(self.new)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved)

    @property
    def persistent_count(self) -> int:
        return len(self.persistent)


def diff_scans(scan_a: Scan, scan_b: Scan) -> DiffResult:
    """Compare scan_b against scan_a.

    - **New**: present in B but not A.
    - **Resolved**: present in A but not B.
    - **Persistent**: present in both.
    """
    a_keys = {_finding_key(f) for f in scan_a.findings}
    b_keys = {_finding_key(f) for f in scan_b.findings}

    new = [f for f in scan_b.findings if _finding_key(f) not in a_keys]
    resolved = [f for f in scan_a.findings if _finding_key(f) not in b_keys]
    persistent = [f for f in scan_b.findings if _finding_key(f) in a_keys]

    return DiffResult(
        scan_a_id=scan_a.id,
        scan_b_id=scan_b.id,
        new=new,
        resolved=resolved,
        persistent=persistent,
    )
