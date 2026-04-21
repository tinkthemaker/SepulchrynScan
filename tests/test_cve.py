"""Tests for sepulchrynscan/cve.py.

Covers:
  - cache hit (no external HTTP)
  - cache miss → NVD fetch → cache write
  - HTTP 429 exponential backoff
  - CVSS fallback chain: v3.1 → v3.0 → v2
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import requests_mock

from sepulchrynscan import config, db
from sepulchrynscan.cve import enrich, fetch_cve_from_nvd
from sepulchrynscan.models import CVE, FindingSource, Host, Service, Severity


def _make_conn():
    """Return a fresh in-memory DB with schema applied."""
    return db.connect(db_path=Path(":memory:"))


def _nvd_response(
    cve_id: str,
    base_score: float | None,
    metric_key: str = "cvssMetricV31",
    description: str = "Test vulnerability",
    published: str = "2021-12-10T00:00:00.000",
    references: list[str] | None = None,
) -> dict:
    """Build a minimal NVD API 2.0 response body."""
    refs = [{"url": u} for u in (references or [])]
    metrics: dict[str, list[dict]] = {}
    if base_score is not None:
        metrics[metric_key] = [{"cvssData": {"baseScore": base_score}}]
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": description}],
                    "published": published,
                    "references": refs,
                    "metrics": metrics,
                }
            }
        ],
    }


class TestFetchCveFromNvd:
    def test_fetches_and_parses_cvss_v31(self, requests_mock: requests_mock.Mocker):
        requests_mock.get(
            config.NVD_API_URL,
            json=_nvd_response("CVE-2021-44228", 9.8),
        )
        with patch("sepulchrynscan.cve.time.sleep"):
            cve = fetch_cve_from_nvd("CVE-2021-44228")

        assert cve.id == "CVE-2021-44228"
        assert cve.cvss_v3_score == 9.8
        assert cve.severity == Severity.CRITICAL
        assert cve.description == "Test vulnerability"
        assert cve.published_at is not None
        assert len(requests_mock.request_history) == 1
        assert requests_mock.request_history[0].qs["cveid"] == ["cve-2021-44228"]

    def test_429_backoff_and_retry(self, requests_mock: requests_mock.Mocker):
        requests_mock.get(
            config.NVD_API_URL,
            [
                {"status_code": 429, "text": "Too Many Requests"},
                {"json": _nvd_response("CVE-2021-44228", 9.8)},
            ],
        )
        with patch("sepulchrynscan.cve.time.sleep") as mock_sleep:
            cve = fetch_cve_from_nvd("CVE-2021-44228")

        assert cve.cvss_v3_score == 9.8
        assert len(requests_mock.request_history) == 2
        # First backoff = NVD_RATE_LIMIT_SLEEP_SEC * 2**0
        mock_sleep.assert_any_call(config.NVD_RATE_LIMIT_SLEEP_SEC)

    def test_missing_cvss_fallback_v30(self, requests_mock: requests_mock.Mocker):
        requests_mock.get(
            config.NVD_API_URL,
            json=_nvd_response("CVE-2021-99999", 7.5, metric_key="cvssMetricV30"),
        )
        with patch("sepulchrynscan.cve.time.sleep"):
            cve = fetch_cve_from_nvd("CVE-2021-99999")
        assert cve.cvss_v3_score == 7.5
        assert cve.severity == Severity.HIGH

    def test_missing_cvss_fallback_v2(self, requests_mock: requests_mock.Mocker):
        requests_mock.get(
            config.NVD_API_URL,
            json=_nvd_response("CVE-2021-99998", 5.0, metric_key="cvssMetricV2"),
        )
        with patch("sepulchrynscan.cve.time.sleep"):
            cve = fetch_cve_from_nvd("CVE-2021-99998")
        assert cve.cvss_v3_score == 5.0
        assert cve.severity == Severity.MEDIUM

    def test_empty_vulnerabilities_returns_defaults(
        self, requests_mock: requests_mock.Mocker
    ):
        requests_mock.get(
            config.NVD_API_URL,
            json={"vulnerabilities": []},
        )
        with patch("sepulchrynscan.cve.time.sleep"):
            cve = fetch_cve_from_nvd("CVE-2021-00000")
        assert cve.cvss_v3_score is None
        assert cve.severity == Severity.NONE
        assert cve.description == ""

    def test_uses_api_key_when_present(
        self, requests_mock: requests_mock.Mocker, monkeypatch
    ):
        monkeypatch.setenv(config.NVD_API_KEY_ENV, "test-key-123")
        requests_mock.get(
            config.NVD_API_URL,
            json=_nvd_response("CVE-2021-44228", 9.8),
        )
        with patch("sepulchrynscan.cve.time.sleep"):
            fetch_cve_from_nvd("CVE-2021-44228")

        assert requests_mock.request_history[0].headers["apiKey"] == "test-key-123"


class TestEnrich:
    def test_cache_hit_no_external_request(self, requests_mock: requests_mock.Mocker):
        conn = _make_conn()
        # Pre-seed cache
        cached = CVE(
            id="CVE-2021-44228",
            cvss_v3_score=9.8,
            severity=Severity.CRITICAL,
            description="Cached",
            published_at=datetime(2021, 12, 10, tzinfo=timezone.utc),
            references=["https://example.com"],
        )
        db.put_cve(conn, cached)

        host = Host(
            ip="127.0.0.1",
            services=[Service(port=8080, cve_ids=["CVE-2021-44228"])],
        )
        findings = enrich(conn, [host])

        assert len(requests_mock.request_history) == 0
        assert len(findings) == 1
        f = findings[0]
        assert f.source == FindingSource.CVE
        assert f.cve_id == "CVE-2021-44228"
        assert f.cvss_v3_score == 9.8
        assert f.severity == Severity.CRITICAL
        assert f.host_ip == "127.0.0.1"
        assert f.port == 8080

    def test_cache_miss_fetches_and_caches(self, requests_mock: requests_mock.Mocker):
        conn = _make_conn()
        requests_mock.get(
            config.NVD_API_URL,
            json=_nvd_response(
                "CVE-2021-44228", 9.8, references=["https://nvd.nist.gov/"]
            ),
        )

        host = Host(
            ip="192.168.1.1",
            services=[
                Service(port=80, protocol="tcp", cve_ids=["CVE-2021-44228"]),
            ],
        )
        with patch("sepulchrynscan.cve.time.sleep"):
            findings = enrich(conn, [host])

        assert len(requests_mock.request_history) == 1
        assert len(findings) == 1
        assert findings[0].cvss_v3_score == 9.8

        # Verify it was written to cache
        cached = db.get_cached_cve(conn, "CVE-2021-44228")
        assert cached is not None
        assert cached.cvss_v3_score == 9.8

    def test_multiple_services_same_cve_deduplicates_requests(
        self, requests_mock: requests_mock.Mocker
    ):
        conn = _make_conn()
        requests_mock.get(
            config.NVD_API_URL,
            json=_nvd_response("CVE-2021-44228", 9.8),
        )

        hosts = [
            Host(
                ip="10.0.0.1",
                services=[Service(port=80, cve_ids=["CVE-2021-44228"])],
            ),
            Host(
                ip="10.0.0.2",
                services=[
                    Service(port=443, cve_ids=["CVE-2021-44228"]),
                    Service(port=8080, cve_ids=["CVE-2021-44228"]),
                ],
            ),
        ]
        with patch("sepulchrynscan.cve.time.sleep"):
            findings = enrich(conn, hosts)

        # Only one NVD request despite three service occurrences
        assert len(requests_mock.request_history) == 1
        assert len(findings) == 3
        assert {f.host_ip for f in findings} == {"10.0.0.1", "10.0.0.2"}
