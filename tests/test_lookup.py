# =============================================================================
#   tests/test_lookup.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Unit tests for lookup.py — cache hit/miss, subdomain walk, empty input,
#   and format_lookup_result output.
#   Run with: pytest tests/test_lookup.py -v
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    with (
        patch("config.LOG_DIR", str(tmp_path / "logs")),
        patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
        patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
        patch("config.DB_PATH", str(tmp_path / "phantom_eye.db")),
        patch("config.WHITELIST_IPS", ["127.0.0.1"]),
        patch("config.WHITELIST_DOMAINS", ["microsoft.com"]),
    ):
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield


from lookup import format_lookup_result, is_ioc_known, lookup_ioc

SAMPLE_CACHE = {
    "ip": {"185.234.1.1", "5.5.5.5"},
    "domain": {"evil.ru", "phishing.example.com"},
}


# ---------------------------------------------------------------------------
#   is_ioc_known
# ---------------------------------------------------------------------------


class TestIsIOCKnown:
    def test_ip_hit(self):
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            assert is_ioc_known("185.234.1.1", "ip")

    def test_ip_miss(self):
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            assert not is_ioc_known("1.2.3.4", "ip")

    def test_domain_exact_hit(self):
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            assert is_ioc_known("evil.ru", "domain")

    def test_domain_subdomain_hit(self):
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            # sub.evil.ru → parent evil.ru is in cache
            assert is_ioc_known("sub.evil.ru", "domain")

    def test_domain_deep_subdomain_hit(self):
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            assert is_ioc_known("a.b.evil.ru", "domain")

    def test_domain_miss(self):
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            assert not is_ioc_known("safe.com", "domain")

    def test_case_insensitive(self):
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            assert is_ioc_known("EVIL.RU", "domain")
            assert is_ioc_known("185.234.1.1", "ip")

    def test_unknown_type(self):
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            assert not is_ioc_known("evil.ru", "url")

    def test_empty_value(self):
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            assert not is_ioc_known("", "domain")


# ---------------------------------------------------------------------------
#   lookup_ioc
# ---------------------------------------------------------------------------


class TestLookupIOC:
    def test_empty_query_returns_error(self):
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("lookup.feeds_loaded", return_value=1000),
            patch("lookup.get_last_feed_time", return_value="2024-01-01"),
        ):
            result = lookup_ioc("")
            assert result["error"] is not None
            assert not result["found"]

    def test_clean_ip(self):
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("lookup.feeds_loaded", return_value=1000),
            patch("lookup.get_last_feed_time", return_value="2024-01-01"),
        ):
            result = lookup_ioc("1.2.3.4")
            assert not result["found"]
            assert result["type"] == "ip"

    def test_malicious_ip(self):
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("lookup.feeds_loaded", return_value=1000),
            patch("lookup.get_last_feed_time", return_value="2024-01-01"),
            patch("lookup.sqlite3"),
        ):
            result = lookup_ioc("185.234.1.1")
            assert result["found"]
            assert result["type"] == "ip"

    def test_url_auto_stripped(self):
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("lookup.feeds_loaded", return_value=1000),
            patch("lookup.get_last_feed_time", return_value="2024-01-01"),
            patch("lookup.sqlite3"),
        ):
            result = lookup_ioc("https://evil.ru/malware")
            assert result["found"]
            assert result["value"] == "evil.ru"

    def test_zero_feeds_warning(self):
        with (
            patch("lookup.get_ioc_cache", return_value={"ip": set(), "domain": set()}),
            patch("lookup.feeds_loaded", return_value=0),
            patch("lookup.get_last_feed_time", return_value="Never"),
        ):
            result = lookup_ioc("1.2.3.4")
            assert result["zero_feeds_warning"]

    def test_type_auto_detection_ip(self):
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("lookup.feeds_loaded", return_value=1000),
            patch("lookup.get_last_feed_time", return_value="2024-01-01"),
        ):
            result = lookup_ioc("8.8.8.8")
            assert result["type"] == "ip"

    def test_type_auto_detection_domain(self):
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("lookup.feeds_loaded", return_value=1000),
            patch("lookup.get_last_feed_time", return_value="2024-01-01"),
        ):
            result = lookup_ioc("safe.com")
            assert result["type"] == "domain"


# ---------------------------------------------------------------------------
#   format_lookup_result
# ---------------------------------------------------------------------------


class TestFormatLookupResult:
    def test_clean_result(self):
        result = {
            "found": False,
            "value": "8.8.8.8",
            "type": "ip",
            "matches": [],
            "total_iocs": 1000,
            "feeds_last_updated": "2024-01-01",
            "zero_feeds_warning": False,
            "error": None,
        }
        text = format_lookup_result(result)
        assert "CLEAN" in text
        assert "8.8.8.8" in text

    def test_malicious_result(self):
        result = {
            "found": True,
            "value": "185.234.1.1",
            "type": "ip",
            "matches": [
                {"threat_type": "c2", "source": "feodo_ips", "first_added": "2024-01-01", "last_updated": "2024-01-02"}
            ],
            "total_iocs": 1000,
            "feeds_last_updated": "2024-01-01",
            "zero_feeds_warning": False,
            "error": None,
        }
        text = format_lookup_result(result)
        assert "MALICIOUS" in text
        assert "C2" in text

    def test_error_result(self):
        result = {
            "found": False,
            "value": "",
            "type": "unknown",
            "matches": [],
            "total_iocs": 0,
            "feeds_last_updated": "Never",
            "zero_feeds_warning": True,
            "error": "Empty query",
        }
        text = format_lookup_result(result)
        assert "ERROR" in text
        assert "Empty query" in text

    def test_zero_feeds_warning(self):
        result = {
            "found": False,
            "value": "1.2.3.4",
            "type": "ip",
            "matches": [],
            "total_iocs": 0,
            "feeds_last_updated": "Never",
            "zero_feeds_warning": True,
            "error": None,
        }
        text = format_lookup_result(result)
        assert "WARNING" in text or "No feeds" in text
