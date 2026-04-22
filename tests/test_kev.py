"""Tests for sepulchrynscan/kev.py.

Covers CISA KEV catalog loading and EPSS batch scoring.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import requests_mock

from sepulchrynscan import config, kev
from sepulchrynscan.models import CVE, Severity


def _kev_response() -> dict:
    return {
        "title": "CISA KEV",
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"},
            {"cveID": "CVE-2021-45046", "dateAdded": "2021-12-14"},
        ],
    }


def _epss_response() -> dict:
    return {
        "data": [
            {"cve": "CVE-2021-44228", "epss": "0.95"},
            {"cve": "CVE-2021-45046", "epss": "0.85"},
        ]
    }


class TestLoadKevCatalog:
    def test_fetches_and_parses(
        self, requests_mock: requests_mock.Mocker, tmp_path: Path
    ):
        requests_mock.get(config.CISA_KEV_URL, json=_kev_response())
        with patch.object(config, "DATA_DIR", tmp_path):
            catalog = kev.load_kev_catalog()
        assert "CVE-2021-44228" in catalog
        assert "CVE-2021-45046" in catalog

    def test_uses_local_cache_when_fresh(
        self, requests_mock: requests_mock.Mocker, tmp_path: Path
    ):
        cache = tmp_path / "cisa_kev.json"
        cache.write_text("""{"vulnerabilities": [{"cveID": "CVE-OLD"}]}""")
        with patch.object(config, "DATA_DIR", tmp_path):
            catalog = kev.load_kev_catalog()
        assert catalog == {"CVE-OLD"}
        assert len(requests_mock.request_history) == 0


class TestFetchEpssScores:
    def test_batch_lookup(self, requests_mock: requests_mock.Mocker):
        requests_mock.get(config.EPSS_API_URL, json=_epss_response())
        scores = kev.fetch_epss_scores(["CVE-2021-44228", "CVE-2021-45046"])
        assert scores == {"CVE-2021-44228": 0.95, "CVE-2021-45046": 0.85}

    def test_empty_list_returns_empty(self):
        assert kev.fetch_epss_scores([]) == {}


class TestEnrichCves:
    def test_mutates_in_place(
        self, requests_mock: requests_mock.Mocker, tmp_path: Path
    ):
        requests_mock.get(config.CISA_KEV_URL, json=_kev_response())
        requests_mock.get(config.EPSS_API_URL, json=_epss_response())

        cves = [
            CVE(id="CVE-2021-44228", severity=Severity.CRITICAL),
            CVE(id="CVE-2021-99999", severity=Severity.HIGH),
        ]
        with patch.object(config, "DATA_DIR", tmp_path):
            kev.enrich_cves(cves)

        assert cves[0].in_kev is True
        assert cves[0].epss_score == 0.95
        assert cves[1].in_kev is False
        assert cves[1].epss_score is None
