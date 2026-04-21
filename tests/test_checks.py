"""Tests for sepulchrynscan/checks.py.

Network I/O is mocked so tests run without real targets.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch


from sepulchrynscan.checks import (
    _check_tls,
    _fetch_headers,
    exposed_services,
    http_headers,
    run_all,
    tls_config,
)
from sepulchrynscan.models import FindingSource, Host, Service, Severity


class MockResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, headers: dict[str, str], status_code: int = 200):
        self.headers = headers
        self.status_code = status_code


# ---------------------------------------------------------------------------
# _fetch_headers
# ---------------------------------------------------------------------------


class TestFetchHeaders:
    @patch("sepulchrynscan.checks.requests.get")
    def test_prefers_https(self, mock_get):
        mock_get.return_value = MockResponse({"server": "nginx"})
        headers = _fetch_headers("127.0.0.1", 443)
        assert headers == {"server": "nginx"}
        assert mock_get.call_args[0][0] == "https://127.0.0.1:443/"

    @patch("sepulchrynscan.checks.requests.get")
    def test_falls_back_to_http(self, mock_get):
        mock_get.side_effect = [
            Exception("Connection refused"),
            MockResponse({"server": "apache"}),
        ]
        headers = _fetch_headers("127.0.0.1", 80)
        assert headers == {"server": "apache"}
        assert mock_get.call_count == 2

    @patch("sepulchrynscan.checks.requests.get")
    def test_returns_none_when_both_fail(self, mock_get):
        mock_get.side_effect = Exception("fail")
        assert _fetch_headers("127.0.0.1", 9999) is None


# ---------------------------------------------------------------------------
# http_headers
# ---------------------------------------------------------------------------


class TestHttpHeaders:
    @patch("sepulchrynscan.checks._fetch_headers")
    def test_finds_missing_headers(self, mock_fetch):
        mock_fetch.return_value = {"server": "nginx"}
        host = Host(ip="10.0.0.1", services=[Service(port=80, name="http")])
        findings = http_headers(host)

        assert len(findings) == 5
        titles = {f.title for f in findings}
        assert titles == {
            "Missing strict-transport-security header",
            "Missing content-security-policy header",
            "Missing x-frame-options header",
            "Missing x-content-type-options header",
            "Missing referrer-policy header",
        }
        # Severities
        assert any(f.severity == Severity.MEDIUM for f in findings)
        assert any(f.severity == Severity.LOW for f in findings)

    @patch("sepulchrynscan.checks._fetch_headers")
    def test_no_findings_when_all_present(self, mock_fetch):
        mock_fetch.return_value = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
        host = Host(ip="10.0.0.1", services=[Service(port=443, name="https")])
        assert http_headers(host) == []

    @patch("sepulchrynscan.checks._fetch_headers")
    def test_no_findings_when_service_not_http(self, mock_fetch):
        mock_fetch.return_value = None
        host = Host(ip="10.0.0.1", services=[Service(port=22, name="ssh")])
        assert http_headers(host) == []


# ---------------------------------------------------------------------------
# tls_config
# ---------------------------------------------------------------------------


class TestCheckTls:
    def _make_mock_ssock(self, version: str = "TLSv1.2", cert_der: bytes | None = None):
        ssock = MagicMock()
        ssock.version.return_value = version
        ssock.getpeercert.return_value = cert_der
        return ssock

    def _make_cert_der(self, not_after: datetime) -> bytes:
        """Build a minimal self-signed DER certificate for testing."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509 import (
            CertificateBuilder,
            Name,
            NameAttribute,
            SubjectAlternativeName,
            DNSName,
        )
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(1000)
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=365))
            .not_valid_after(not_after)
            .add_extension(SubjectAlternativeName([DNSName("test")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    @patch("sepulchrynscan.checks.socket.create_connection")
    @patch("sepulchrynscan.checks.ssl.create_default_context")
    def test_flags_outdated_tls(self, mock_ctx_factory, mock_conn):
        ssock = self._make_mock_ssock(version="TLSv1.1")
        mock_ctx_factory.return_value.wrap_socket.return_value.__enter__ = (
            lambda *a: ssock
        )
        mock_ctx_factory.return_value.wrap_socket.return_value.__exit__ = (
            lambda *a: None
        )

        findings = _check_tls("10.0.0.1", 443)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "TLSv1.1" in findings[0].description

    @patch("sepulchrynscan.checks.socket.create_connection")
    @patch("sepulchrynscan.checks.ssl.create_default_context")
    def test_flags_expired_cert(self, mock_ctx_factory, mock_conn):
        expired = datetime.now(timezone.utc) - timedelta(days=5)
        ssock = self._make_mock_ssock(
            version="TLSv1.2", cert_der=self._make_cert_der(expired)
        )
        mock_ctx_factory.return_value.wrap_socket.return_value.__enter__ = (
            lambda *a: ssock
        )
        mock_ctx_factory.return_value.wrap_socket.return_value.__exit__ = (
            lambda *a: None
        )

        findings = _check_tls("10.0.0.1", 443)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("expired" in f.title.lower() for f in findings)

    @patch("sepulchrynscan.checks.socket.create_connection")
    @patch("sepulchrynscan.checks.ssl.create_default_context")
    def test_flags_cert_expiring_soon(self, mock_ctx_factory, mock_conn):
        soon = datetime.now(timezone.utc) + timedelta(days=15)
        ssock = self._make_mock_ssock(
            version="TLSv1.2", cert_der=self._make_cert_der(soon)
        )
        mock_ctx_factory.return_value.wrap_socket.return_value.__enter__ = (
            lambda *a: ssock
        )
        mock_ctx_factory.return_value.wrap_socket.return_value.__exit__ = (
            lambda *a: None
        )

        findings = _check_tls("10.0.0.1", 443)
        assert any(f.severity == Severity.MEDIUM for f in findings)
        assert any("expiring soon" in f.title.lower() for f in findings)

    @patch("sepulchrynscan.checks.socket.create_connection")
    @patch("sepulchrynscan.checks.ssl.create_default_context")
    def test_no_findings_for_good_tls(self, mock_ctx_factory, mock_conn):
        future = datetime.now(timezone.utc) + timedelta(days=90)
        ssock = self._make_mock_ssock(
            version="TLSv1.2", cert_der=self._make_cert_der(future)
        )
        mock_ctx_factory.return_value.wrap_socket.return_value.__enter__ = (
            lambda *a: ssock
        )
        mock_ctx_factory.return_value.wrap_socket.return_value.__exit__ = (
            lambda *a: None
        )

        findings = _check_tls("10.0.0.1", 443)
        assert findings == []

    @patch("sepulchrynscan.checks.socket.create_connection")
    def test_returns_empty_on_connection_failure(self, mock_conn):
        mock_conn.side_effect = Exception("Connection refused")
        assert _check_tls("10.0.0.1", 443) == []


class TestTlsConfig:
    @patch("sepulchrynscan.checks._check_tls")
    def test_only_checks_tls_named_services(self, mock_check):
        mock_check.return_value = [
            MagicMock(severity=Severity.HIGH),
        ]
        host = Host(
            ip="10.0.0.1",
            services=[
                Service(port=443, name="https"),
                Service(port=80, name="http"),
                Service(port=22, name="ssh"),
            ],
        )
        tls_config(host)
        assert mock_check.call_count == 1
        assert mock_check.call_args[0] == ("10.0.0.1", 443)


# ---------------------------------------------------------------------------
# exposed_services
# ---------------------------------------------------------------------------


class TestExposedServices:
    def test_flags_known_dangerous_services(self):
        host = Host(
            ip="10.0.0.1",
            services=[
                Service(port=23, name="telnet"),
                Service(port=3389, name="ms-wbt-server"),
                Service(port=8080, name="http-proxy"),
            ],
        )
        findings = exposed_services(host)
        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert severities == {Severity.CRITICAL, Severity.HIGH}

    def test_no_findings_for_safe_services(self):
        host = Host(
            ip="10.0.0.1",
            services=[
                Service(port=80, name="http"),
                Service(port=443, name="https"),
                Service(port=22, name="ssh"),
            ],
        )
        assert exposed_services(host) == []


# ---------------------------------------------------------------------------
# run_all
# ---------------------------------------------------------------------------


class TestRunAll:
    @patch("sepulchrynscan.checks.http_headers")
    @patch("sepulchrynscan.checks.tls_config")
    @patch("sepulchrynscan.checks.exposed_services")
    def test_aggregates_all_findings(self, mock_exp, mock_tls, mock_http):
        mock_http.return_value = [MagicMock(source=FindingSource.HTTP_HEADERS)]
        mock_tls.return_value = [MagicMock(source=FindingSource.TLS)]
        mock_exp.return_value = [MagicMock(source=FindingSource.EXPOSED_SERVICE)]

        hosts = [Host(ip="10.0.0.1", services=[])]
        findings = run_all(hosts)

        assert len(findings) == 3
        mock_http.assert_called_once_with(hosts[0])
        mock_tls.assert_called_once_with(hosts[0])
        mock_exp.assert_called_once_with(hosts[0])
