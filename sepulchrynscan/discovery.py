"""Discovery stage: Nmap -sV + vulners NSE → list[Host].

Contract:
    run(target: str) -> list[Host]

The returned Hosts carry Services whose `cve_ids` are populated from the
`vulners` NSE output. CVE *scoring* is the responsibility of cve.py; this
module does not touch the NVD API.
"""

from __future__ import annotations

import re
import warnings

import nmap

from . import config
from .models import Host, Service

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def run(target: str, arguments: str | None = None) -> list[Host]:
    """Run Nmap service + vulners scan against `target`.

    Returns an empty list if the target is unreachable or Nmap fails.
    Emits a warning in those cases so the caller can log it.
    """
    scanner = nmap.PortScanner()
    nmap_args = arguments or config.NMAP_ARGS
    try:
        scanner.scan(hosts=target, arguments=nmap_args)
    except nmap.PortScannerError as exc:
        warnings.warn(f"Nmap scan failed for {target}: {exc}")
        return []

    hosts: list[Host] = []
    for host_ip in scanner.all_hosts():
        host_data = scanner[host_ip]
        if host_data.state() != "up":
            continue

        services: list[Service] = []
        for protocol in ("tcp", "udp"):
            if protocol not in host_data:
                continue
            for port, port_data in host_data[protocol].items():
                if port_data.get("state") != "open":
                    continue

                script_output = port_data.get("script", {}).get("vulners", "")
                cve_ids = (
                    sorted(set(_CVE_RE.findall(script_output))) if script_output else []
                )

                conf_raw = port_data.get("conf")
                confidence = float(conf_raw) if conf_raw is not None else None

                services.append(
                    Service(
                        port=int(port),
                        protocol=protocol,
                        name=port_data.get("name", ""),
                        product=port_data.get("product", ""),
                        version=port_data.get("version", ""),
                        confidence=confidence,
                        banner=port_data.get("extrainfo", ""),
                        cve_ids=cve_ids,
                    )
                )

        if services:
            hosts.append(
                Host(
                    ip=host_ip,
                    hostname=host_data.hostname() or "",
                    services=services,
                )
            )

    if not hosts:
        warnings.warn(f"No reachable hosts or open ports found for {target}")

    return hosts
