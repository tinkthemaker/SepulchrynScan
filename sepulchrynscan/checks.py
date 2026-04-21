"""Custom checks. Three functions, one file. No plugin loader (by design).

Contract:
    run_all(hosts) -> list[Finding]

Each check emits zero or more Findings. Add a 4th by writing a 4th function
and calling it from run_all — do NOT introduce a loader.
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone

import requests
import urllib3
from cryptography import x509

from .models import Finding, FindingSource, Host, Severity

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# HTTP security headers
# ---------------------------------------------------------------------------

_REQUIRED_HEADERS: dict[str, Severity] = {
    "strict-transport-security": Severity.MEDIUM,
    "content-security-policy": Severity.MEDIUM,
    "x-frame-options": Severity.LOW,
    "x-content-type-options": Severity.LOW,
    "referrer-policy": Severity.LOW,
}


def _fetch_headers(host_ip: str, port: int) -> dict[str, str] | None:
    """Try HTTPS then HTTP; return response headers dict or None."""
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{host_ip}:{port}/"
            resp = requests.get(
                url,
                timeout=5,
                verify=False,
                allow_redirects=True,
            )
            return dict(resp.headers)
        except Exception:
            continue
    return None


def http_headers(host: Host) -> list[Finding]:
    """Check HTTP response headers for missing security directives."""
    findings: list[Finding] = []
    for svc in host.services:
        headers = _fetch_headers(host.ip, svc.port)
        if headers is None:
            continue

        lowered = {k.lower(): v for k, v in headers.items()}
        for header, severity in _REQUIRED_HEADERS.items():
            if header not in lowered:
                findings.append(
                    Finding(
                        source=FindingSource.HTTP_HEADERS,
                        severity=severity,
                        title=f"Missing {header} header",
                        description=(
                            f"The HTTP response from {host.ip}:{svc.port} "
                            f"does not include the {header} header."
                        ),
                        host_ip=host.ip,
                        port=svc.port,
                        protocol=svc.protocol,
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# TLS configuration
# ---------------------------------------------------------------------------

_TLS_NAME_RE = re.compile(r"https|ssl|tls", re.IGNORECASE)


def _check_tls(host_ip: str, port: int) -> list[Finding]:
    """Inspect TLS version and certificate expiry."""
    findings: list[Finding] = []
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host_ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host_ip) as ssock:
                version = ssock.version()
                if version in ("TLSv1", "TLSv1.1"):
                    findings.append(
                        Finding(
                            source=FindingSource.TLS,
                            severity=Severity.HIGH,
                            title="Outdated TLS version",
                            description=(
                                f"Server at {host_ip}:{port} negotiates {version}, "
                                f"which is below TLS 1.2."
                            ),
                            host_ip=host_ip,
                            port=port,
                        )
                    )

                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    cert = x509.load_der_x509_certificate(cert_der)
                    try:
                        not_after = cert.not_valid_after_utc
                    except AttributeError:
                        not_after = cert.not_valid_after
                        if not_after.tzinfo is None:
                            not_after = not_after.replace(tzinfo=timezone.utc)

                    now = datetime.now(timezone.utc)
                    days_left = (not_after - now).days

                    if days_left < 0:
                        findings.append(
                            Finding(
                                source=FindingSource.TLS,
                                severity=Severity.CRITICAL,
                                title="Expired TLS certificate",
                                description=(
                                    f"TLS certificate for {host_ip}:{port} expired "
                                    f"{abs(days_left)} days ago."
                                ),
                                host_ip=host_ip,
                                port=port,
                            )
                        )
                    elif days_left < 30:
                        findings.append(
                            Finding(
                                source=FindingSource.TLS,
                                severity=Severity.MEDIUM,
                                title="TLS certificate expiring soon",
                                description=(
                                    f"TLS certificate for {host_ip}:{port} expires "
                                    f"in {days_left} days."
                                ),
                                host_ip=host_ip,
                                port=port,
                            )
                        )
    except Exception:
        # Service does not speak TLS or is unreachable — skip silently
        pass

    return findings


def tls_config(host: Host) -> list[Finding]:
    """Check TLS on services whose name suggests they speak it."""
    findings: list[Finding] = []
    for svc in host.services:
        if _TLS_NAME_RE.search(svc.name):
            findings.extend(_check_tls(host.ip, svc.port))
    return findings


# ---------------------------------------------------------------------------
# Exposed services
# ---------------------------------------------------------------------------

_EXPOSED_RULES: dict[tuple[int, str], Severity] = {
    (23, "telnet"): Severity.CRITICAL,
    (21, "ftp"): Severity.HIGH,
    (3389, "ms-wbt-server"): Severity.HIGH,
    (3389, "rdp"): Severity.HIGH,
    (445, "microsoft-ds"): Severity.HIGH,
    (445, "smb"): Severity.HIGH,
    (139, "netbios-ssn"): Severity.HIGH,
    (161, "snmp"): Severity.HIGH,
    (6379, "redis"): Severity.CRITICAL,
    (27017, "mongodb"): Severity.CRITICAL,
    (9200, "elastic"): Severity.HIGH,
    (3306, "mysql"): Severity.HIGH,
    (5432, "postgresql"): Severity.HIGH,
    (1433, "ms-sql-s"): Severity.HIGH,
    (1521, "oracle"): Severity.HIGH,
    (5900, "vnc"): Severity.CRITICAL,
    (5901, "vnc"): Severity.CRITICAL,
}


def exposed_services(host: Host) -> list[Finding]:
    """Flag dangerous services exposed on well-known ports."""
    findings: list[Finding] = []
    for svc in host.services:
        key = (svc.port, svc.name.lower())
        severity = _EXPOSED_RULES.get(key)
        if severity is not None:
            findings.append(
                Finding(
                    source=FindingSource.EXPOSED_SERVICE,
                    severity=severity,
                    title=f"Exposed service: {svc.name} on port {svc.port}",
                    description=(
                        f"The {svc.name} service is exposed on port {svc.port}, "
                        f"which may present a security risk."
                    ),
                    host_ip=host.ip,
                    port=svc.port,
                    protocol=svc.protocol,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_all(hosts: list[Host]) -> list[Finding]:
    findings: list[Finding] = []
    for host in hosts:
        findings.extend(http_headers(host))
        findings.extend(tls_config(host))
        findings.extend(exposed_services(host))
    return findings
