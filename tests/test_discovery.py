"""Tests for sepulchrynscan/discovery.py.

Nmap is mocked out so these tests run without the binary on PATH.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sepulchrynscan import discovery
from sepulchrynscan.models import Host, Service


class _MockHost:
    """Minimal stand-in for python-nmap's host result object."""

    def __init__(
        self,
        state: str = "up",
        hostname: str = "",
        protocols: dict | None = None,
    ):
        self._state = state
        self._hostname = hostname
        self._protocols = protocols or {}

    def state(self) -> str:
        return self._state

    def hostname(self) -> str:
        return self._hostname

    def __contains__(self, protocol: str) -> bool:
        return protocol in self._protocols

    def __getitem__(self, protocol: str):
        return self._protocols[protocol]


def _make_scanner(hosts: dict[str, _MockHost]) -> MagicMock:
    scanner = MagicMock()
    scanner.all_hosts.return_value = list(hosts.keys())
    scanner.__getitem__.side_effect = hosts.__getitem__
    return scanner


class TestRun:
    @patch("sepulchrynscan.discovery.nmap.PortScanner")
    def test_extracts_services_and_cves(self, mock_ps):
        scanner = _make_scanner(
            {
                "127.0.0.1": _MockHost(
                    state="up",
                    hostname="localhost",
                    protocols={
                        "tcp": {
                            80: {
                                "state": "open",
                                "name": "http",
                                "product": "Apache httpd",
                                "version": "2.4.41",
                                "conf": "10",
                                "extrainfo": "",
                                "script": {
                                    "vulners": (
                                        "cpe:/a:apache:http_server:2.4.41\n"
                                        "|      CVE-2021-44790   9.8   https://vulners.com/cve/CVE-2021-44790\n"
                                        "|      CVE-2021-41773   7.5   https://vulners.com/cve/CVE-2021-41773"
                                    )
                                },
                            }
                        }
                    },
                )
            }
        )
        mock_ps.return_value = scanner

        hosts = discovery.run("127.0.0.1")

        assert len(hosts) == 1
        host = hosts[0]
        assert isinstance(host, Host)
        assert host.ip == "127.0.0.1"
        assert host.hostname == "localhost"
        assert len(host.services) == 1

        svc = host.services[0]
        assert isinstance(svc, Service)
        assert svc.port == 80
        assert svc.protocol == "tcp"
        assert svc.name == "http"
        assert svc.product == "Apache httpd"
        assert svc.version == "2.4.41"
        assert svc.confidence == 10.0
        assert svc.cve_ids == ["CVE-2021-41773", "CVE-2021-44790"]  # sorted

    @patch("sepulchrynscan.discovery.nmap.PortScanner")
    def test_no_open_ports_returns_empty(self, mock_ps):
        scanner = _make_scanner(
            {
                "192.168.1.1": _MockHost(
                    state="up",
                    protocols={"tcp": {22: {"state": "filtered"}}},
                )
            }
        )
        mock_ps.return_value = scanner

        with pytest.warns(UserWarning, match="No reachable hosts"):
            hosts = discovery.run("192.168.1.1")

        assert hosts == []

    @patch("sepulchrynscan.discovery.nmap.PortScanner")
    def test_host_down_returns_empty(self, mock_ps):
        scanner = _make_scanner(
            {
                "10.0.0.1": _MockHost(
                    state="down",
                    protocols={},
                )
            }
        )
        mock_ps.return_value = scanner

        with pytest.warns(UserWarning, match="No reachable hosts"):
            hosts = discovery.run("10.0.0.1")

        assert hosts == []

    @patch("sepulchrynscan.discovery.nmap.PortScanner")
    def test_nmap_error_returns_empty_with_warning(self, mock_ps):
        scanner = MagicMock()
        scanner.scan.side_effect = discovery.nmap.PortScannerError("nmap not found")
        mock_ps.return_value = scanner

        with pytest.warns(UserWarning, match="Nmap scan failed"):
            hosts = discovery.run("127.0.0.1")

        assert hosts == []

    @patch("sepulchrynscan.discovery.nmap.PortScanner")
    def test_multiple_hosts_and_protocols(self, mock_ps):
        scanner = _make_scanner(
            {
                "10.0.0.1": _MockHost(
                    state="up",
                    protocols={
                        "tcp": {
                            80: {
                                "state": "open",
                                "name": "http",
                                "product": "",
                                "version": "",
                                "script": {"vulners": "CVE-2023-0001"},
                            }
                        },
                        "udp": {
                            53: {
                                "state": "open",
                                "name": "domain",
                                "product": "",
                                "version": "",
                                "script": {},
                            }
                        },
                    },
                ),
                "10.0.0.2": _MockHost(
                    state="up",
                    protocols={
                        "tcp": {
                            443: {
                                "state": "open",
                                "name": "https",
                                "product": "",
                                "version": "",
                                "script": {},
                            }
                        }
                    },
                ),
            }
        )
        mock_ps.return_value = scanner

        hosts = discovery.run("10.0.0.0/24")

        assert len(hosts) == 2
        ips = {h.ip for h in hosts}
        assert ips == {"10.0.0.1", "10.0.0.2"}

        host_1 = next(h for h in hosts if h.ip == "10.0.0.1")
        assert len(host_1.services) == 2
        ports = {s.port for s in host_1.services}
        assert ports == {80, 53}

    @patch("sepulchrynscan.discovery.nmap.PortScanner")
    def test_deduplicates_cve_ids(self, mock_ps):
        scanner = _make_scanner(
            {
                "127.0.0.1": _MockHost(
                    state="up",
                    protocols={
                        "tcp": {
                            80: {
                                "state": "open",
                                "name": "http",
                                "product": "",
                                "version": "",
                                "script": {
                                    "vulners": (
                                        "CVE-2021-44228\n"
                                        "CVE-2021-44228\n"  # duplicate
                                        "CVE-2021-45046"
                                    )
                                },
                            }
                        }
                    },
                )
            }
        )
        mock_ps.return_value = scanner

        hosts = discovery.run("127.0.0.1")
        assert hosts[0].services[0].cve_ids == ["CVE-2021-44228", "CVE-2021-45046"]

    @patch("sepulchrynscan.discovery.nmap.PortScanner")
    def test_arguments_override(self, mock_ps):
        scanner = _make_scanner({})
        mock_ps.return_value = scanner
        discovery.run("127.0.0.1", arguments="-sV -p 3000 --script vulners")
        assert scanner.scan.call_args[1]["arguments"] == "-sV -p 3000 --script vulners"
