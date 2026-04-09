# =============================================================================
#   tests/test_feeds.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Unit tests for feeds.py — feed parsing and column detection.
#   Run with: pytest tests/test_feeds.py -v
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    """Prevent logger from writing to C:\\SecurityLogs."""
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


from feeds import _detect_ip_column, parse_feed

# ---------------------------------------------------------------------------
#   _detect_ip_column
# ---------------------------------------------------------------------------


class TestDetectIPColumn:
    def test_feodo_header(self):
        lines = ["# first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware"]
        assert _detect_ip_column(lines, "feodo_csv") == 1

    def test_abuse_ssl_header(self):
        lines = ["# Listingdate,DstIP,DstPort"]
        # "dstip" maps to column 1
        assert _detect_ip_column(lines, "abuse_ssl_csv") == 1

    def test_fallback_feodo(self):
        lines = ["1.2.3.4,5.6.7.8"]  # no header
        assert _detect_ip_column(lines, "feodo_csv") == 1

    def test_fallback_abuse_ssl(self):
        lines = []
        assert _detect_ip_column(lines, "abuse_ssl_csv") == 1

    def test_generic_ip_header(self):
        lines = ["# date,ip,port"]
        assert _detect_ip_column(lines, "feodo_csv") == 1


# ---------------------------------------------------------------------------
#   parse_feed — plain_ip
# ---------------------------------------------------------------------------


class TestParseFeedPlainIP:
    cfg = {"format": "plain_ip", "type": "ip"}

    def test_valid_public_ips(self):
        content = "1.2.3.4\n5.6.7.8\n"
        result = parse_feed(content, "test", self.cfg)
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result

    def test_skips_comments(self):
        content = "# comment\n; also comment\n1.2.3.4\n"
        result = parse_feed(content, "test", self.cfg)
        assert result == ["1.2.3.4"]

    def test_skips_private_ips(self):
        content = "192.168.1.1\n10.0.0.1\n8.8.8.8\n"
        result = parse_feed(content, "test", self.cfg)
        assert "192.168.1.1" not in result
        assert "10.0.0.1" not in result
        assert "8.8.8.8" in result

    def test_deduplication(self):
        content = "1.2.3.4\n1.2.3.4\n1.2.3.4\n"
        result = parse_feed(content, "test", self.cfg)
        assert result.count("1.2.3.4") == 1

    def test_empty_content(self):
        assert parse_feed("", "test", self.cfg) == []

    def test_skips_invalid(self):
        content = "not-an-ip\n999.999.999.999\n1.2.3.4\n"
        result = parse_feed(content, "test", self.cfg)
        assert "not-an-ip" not in result
        assert "1.2.3.4" in result


# ---------------------------------------------------------------------------
#   parse_feed — feodo_csv
# ---------------------------------------------------------------------------


class TestParseFeedFeodoCSV:
    cfg = {"format": "feodo_csv", "type": "ip"}

    def test_standard_format(self):
        content = (
            "# first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n"
            "2024-01-01 00:00:00,185.234.1.1,443,online,2024-01-01,Emotet\n"
        )
        result = parse_feed(content, "feodo_ips", self.cfg)
        assert "185.234.1.1" in result

    def test_skips_private_in_csv(self):
        content = "# first_seen_utc,dst_ip,dst_port\n2024-01-01,192.168.1.1,443\n2024-01-01,185.234.1.1,443\n"
        result = parse_feed(content, "feodo_ips", self.cfg)
        assert "192.168.1.1" not in result
        assert "185.234.1.1" in result


# ---------------------------------------------------------------------------
#   parse_feed — url_extract
# ---------------------------------------------------------------------------


class TestParseFeedURLExtract:
    cfg = {"format": "url_extract", "type": "domain"}

    def test_extracts_domain(self):
        content = "https://evil.ru/malware.exe\n"
        result = parse_feed(content, "urlhaus", self.cfg)
        assert "evil.ru" in result

    def test_strips_www(self):
        content = "https://www.phishing.example.com/page\n"
        result = parse_feed(content, "urlhaus", self.cfg)
        assert "phishing.example.com" in result

    def test_skips_whitelisted(self):
        content = "https://microsoft.com/download\n"
        result = parse_feed(content, "urlhaus", self.cfg)
        assert "microsoft.com" not in result

    def test_skips_comments(self):
        content = "# https://evil.ru\nhttps://real-evil.ru\n"
        result = parse_feed(content, "urlhaus", self.cfg)
        assert "evil.ru" not in result
        assert "real-evil.ru" in result


# ---------------------------------------------------------------------------
#   parse_feed — plain_domain
# ---------------------------------------------------------------------------


class TestParseFeedPlainDomain:
    cfg = {"format": "plain_domain", "type": "domain"}

    def test_valid_domain(self):
        content = "evil.ru\nbad-actor.com\n"
        result = parse_feed(content, "botvrij", self.cfg)
        assert "evil.ru" in result
        assert "bad-actor.com" in result

    def test_skips_whitelisted(self):
        content = "microsoft.com\nevil.ru\n"
        result = parse_feed(content, "botvrij", self.cfg)
        assert "microsoft.com" not in result
        assert "evil.ru" in result

    def test_whitelist_checked_once(self):
        """Whitelist should only be applied once (no double-check regression)."""
        content = "evil.ru\n"
        # Both inline and final check would have caught "microsoft.com"
        # but only the final check should run now — verify no double-call error
        result = parse_feed(content, "botvrij", self.cfg)
        assert "evil.ru" in result
