"""Pydantic data contracts. The inter-module spine of SepulchrynScan.

Every module consumes and emits these models. Do not break their shape
without updating every consumer in the same change.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"

    @classmethod
    def from_cvss(cls, score: float | None) -> "Severity":
        if score is None:
            return cls.NONE
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.NONE


class FindingSource(str, Enum):
    CVE = "cve"
    HTTP_HEADERS = "http_headers"
    TLS = "tls"
    EXPOSED_SERVICE = "exposed_service"
    ADMIN_PANEL = "admin_panel"


class ScanStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class CVE(BaseModel):
    """Authoritative CVE record sourced from NVD API 2.0."""

    model_config = ConfigDict(use_enum_values=False)

    id: str
    cvss_v3_score: float | None = None
    severity: Severity = Severity.NONE
    description: str = ""
    published_at: datetime | None = None
    references: list[str] = Field(default_factory=list)
    fetched_at: datetime = Field(default_factory=_utcnow)
    in_kev: bool = False
    epss_score: float | None = None
    exploit_refs: list[str] = Field(default_factory=list)


class Service(BaseModel):
    """Single discovered service on a host."""

    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    confidence: float | None = None
    banner: str = ""
    cve_ids: list[str] = Field(default_factory=list)


class Host(BaseModel):
    """Discovered host with its services."""

    ip: str
    hostname: str = ""
    services: list[Service] = Field(default_factory=list)


class Finding(BaseModel):
    """A single reportable issue. Outputs of CVE enrichment and custom checks
    both flatten into this shape so reporting has one thing to render."""

    model_config = ConfigDict(use_enum_values=False)

    source: FindingSource
    severity: Severity
    title: str
    description: str = ""
    remediation: str = ""

    host_ip: str
    port: int | None = None
    protocol: str = "tcp"

    cve_id: str | None = None
    cvss_v3_score: float | None = None
    references: list[str] = Field(default_factory=list)
    in_kev: bool = False
    epss_score: float | None = None
    exploit_refs: list[str] = Field(default_factory=list)


class Scan(BaseModel):
    """Top-level scan record. Aggregates hosts and findings for reporting."""

    model_config = ConfigDict(use_enum_values=False)

    id: str
    target: str
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = None
    status: ScanStatus = ScanStatus.RUNNING
    hosts: list[Host] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
