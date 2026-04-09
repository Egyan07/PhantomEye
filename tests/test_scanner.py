# =============================================================================
#   tests/test_scanner.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Unit tests for scanner.py — firewall log scanner, DNS cache scanner,
#   and email header analyser.
#   Run with: pytest tests/test_scanner.py -v
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import sqlite3
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
#   Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    """
    Patch config values to tmp_path locations, create the SQLite tables
    that scanner.py connects to directly, and suppress msg.exe calls.

    scanner.py does ``from config import DB_PATH, FIREWALL_LOG, ...`` at the
    top level, so we must patch both the config module AND the scanner module's
    own references to ensure the test-time values are used.
    """
    db_path = str(tmp_path / "phantom_eye.db")
    log_path = str(tmp_path / "pfirewall.log")

    with (
        patch("config.LOG_DIR", str(tmp_path / "logs")),
        patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
        patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
        patch("config.DB_PATH", db_path),
        patch("config.FIREWALL_LOG", log_path),
        patch("config.FIREWALL_LOG_DAYS", 1),
        patch("config.ADMIN_PC", "TESTPC"),
        patch("config.ALERT_DEDUPE_HOURS", 24),
        patch("config.EMAIL_ENABLED", False),
        patch("config.WHITELIST_IPS", ["127.0.0.1", "0.0.0.0"]),
        patch("config.WHITELIST_DOMAINS", ["microsoft.com", "google.com"]),
        patch("scanner.FIREWALL_LOG", log_path),
        patch("scanner.FIREWALL_LOG_DAYS", 1),
        patch("scanner.DB_PATH", db_path),
        patch("alerts.DB_PATH", db_path),
        patch("alerts.ADMIN_PC", "TESTPC"),
        patch("alerts.ALERT_DEDUPE_HOURS", 24),
        patch("alerts.EMAIL_ENABLED", False),
        patch("subprocess.run"),
    ):
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)

        # Create real SQLite tables so scanner's sqlite3.connect(DB_PATH) works
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                type         TEXT,
                value        TEXT,
                threat_type  TEXT,
                source       TEXT,
                first_added  TEXT,
                last_updated TEXT,
                UNIQUE(type, value)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS feed_status (
                feed_name    TEXT PRIMARY KEY,
                label        TEXT,
                last_updated TEXT,
                ioc_count    INTEGER,
                status       TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT,
                severity     TEXT,
                alert_type   TEXT,
                ioc_value    TEXT,
                ioc_type     TEXT,
                source_feed  TEXT,
                context      TEXT,
                details      TEXT
            )
        """)
        conn.commit()
        conn.close()
        yield


SAMPLE_CACHE = {
    "ip": {"185.234.1.1", "5.5.5.5"},
    "domain": {"evil.ru", "malware.bad.com"},
}

EMPTY_CACHE = {
    "ip": set(),
    "domain": set(),
}


from scanner import analyse_email_headers, scan_dns_cache, scan_firewall_logs

# ---------------------------------------------------------------------------
#   Helpers
# ---------------------------------------------------------------------------


def _today_str():
    """Return today's date as YYYY-MM-DD."""
    return datetime.now().strftime("%Y-%m-%d")


def _now_str():
    """Return current datetime as YYYY-MM-DD HH:MM:SS."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _write_firewall_log(tmp_path, lines):
    """Write firewall log lines to the patched log path."""
    log_path = tmp_path / "pfirewall.log"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ===========================================================================
#   Task 1 — Firewall log scanner (11 tests)
# ===========================================================================


class TestFirewallScanner:
    def test_no_log_file_returns_empty(self, tmp_path):
        """When the firewall log file does not exist, return an empty list."""
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            result = scan_firewall_logs()
        assert result == []

    def test_detects_malicious_dst_ip_allow(self, tmp_path):
        """ALLOW + known malicious dst IP should produce a hit."""
        now = _now_str()
        _write_firewall_log(
            tmp_path,
            [
                "#Fields: date time action protocol src-ip dst-ip src-port dst-port",
                f"{now.split()[0]} {now.split()[1]} ALLOW TCP 192.168.1.10 185.234.1.1 54321 443",
            ],
        )
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            hits = scan_firewall_logs()
        assert len(hits) == 1
        assert hits[0]["ioc"] == "185.234.1.1"
        assert hits[0]["direction"] == "outbound"
        assert hits[0]["action"] == "ALLOW"

    def test_detects_malicious_dst_ip_drop(self, tmp_path):
        """DROP + known malicious dst IP should produce a hit."""
        now = _now_str()
        _write_firewall_log(
            tmp_path,
            [
                "#Fields: date time action protocol src-ip dst-ip src-port dst-port",
                f"{now.split()[0]} {now.split()[1]} DROP TCP 192.168.1.10 5.5.5.5 54321 443",
            ],
        )
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            hits = scan_firewall_logs()
        assert len(hits) == 1
        assert hits[0]["ioc"] == "5.5.5.5"
        assert hits[0]["action"] == "DROP"

    def test_detects_malicious_src_ip(self, tmp_path):
        """Inbound from a known malicious IP should produce a hit."""
        now = _now_str()
        _write_firewall_log(
            tmp_path,
            [
                "#Fields: date time action protocol src-ip dst-ip src-port dst-port",
                f"{now.split()[0]} {now.split()[1]} DROP TCP 185.234.1.1 192.168.1.10 80 54321",
            ],
        )
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            hits = scan_firewall_logs()
        assert any(h["direction"] == "inbound" for h in hits)
        inbound = [h for h in hits if h["direction"] == "inbound"]
        assert inbound[0]["ioc"] == "185.234.1.1"

    def test_skips_old_entries(self, tmp_path):
        """Entries older than FIREWALL_LOG_DAYS should be ignored."""
        old_date = (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S")
        _write_firewall_log(
            tmp_path,
            [
                f"{old_date.split()[0]} {old_date.split()[1]} ALLOW TCP 192.168.1.10 185.234.1.1 54321 443",
            ],
        )
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            hits = scan_firewall_logs()
        assert hits == []

    def test_skips_comments_and_blanks(self, tmp_path):
        """Comment lines and blank lines should be skipped without errors."""
        now = _now_str()
        _write_firewall_log(
            tmp_path,
            [
                "#Version: 1.5",
                "#Fields: date time action protocol src-ip dst-ip src-port dst-port",
                "",
                "# This is a comment",
                "",
                f"{now.split()[0]} {now.split()[1]} ALLOW TCP 192.168.1.10 8.8.8.8 54321 53",
            ],
        )
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            hits = scan_firewall_logs()
        assert hits == []

    def test_clean_ip_not_flagged(self, tmp_path):
        """An IP not in the threat cache should produce no hits."""
        now = _now_str()
        _write_firewall_log(
            tmp_path,
            [
                f"{now.split()[0]} {now.split()[1]} ALLOW TCP 192.168.1.10 8.8.8.8 54321 53",
            ],
        )
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            hits = scan_firewall_logs()
        assert hits == []

    def test_deduplicates_same_ip(self, tmp_path):
        """The same malicious IP appearing multiple times should produce only one hit."""
        now = _now_str()
        _write_firewall_log(
            tmp_path,
            [
                f"{now.split()[0]} {now.split()[1]} ALLOW TCP 192.168.1.10 185.234.1.1 54321 443",
                f"{now.split()[0]} {now.split()[1]} ALLOW TCP 192.168.1.10 185.234.1.1 54322 443",
                f"{now.split()[0]} {now.split()[1]} ALLOW TCP 192.168.1.10 185.234.1.1 54323 443",
            ],
        )
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            hits = scan_firewall_logs()
        dst_hits = [h for h in hits if h["direction"] == "outbound"]
        assert len(dst_hits) == 1

    def test_callback_receives_messages(self, tmp_path):
        """The callback should be called with status messages."""
        now = _now_str()
        _write_firewall_log(
            tmp_path,
            [
                f"{now.split()[0]} {now.split()[1]} ALLOW TCP 192.168.1.10 185.234.1.1 54321 443",
            ],
        )
        messages = []
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            scan_firewall_logs(callback=messages.append)
        assert len(messages) > 0
        assert any("[HIT]" in m for m in messages)

    def test_permission_error_handled(self, tmp_path):
        """PermissionError when reading the log should be caught, not crash."""
        log_path = tmp_path / "pfirewall.log"
        log_path.write_text("dummy", encoding="utf-8")

        messages = []
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("builtins.open", side_effect=PermissionError("Access denied")),
        ):
            hits = scan_firewall_logs(callback=messages.append)
        assert hits == []
        assert any("ERROR" in m or "Cannot read" in m for m in messages)

    def test_private_src_ip_ignored(self, tmp_path):
        """A private src IP should never be flagged even if it were in the cache."""
        now = _now_str()
        # Private source, clean public destination
        _write_firewall_log(
            tmp_path,
            [
                f"{now.split()[0]} {now.split()[1]} ALLOW TCP 192.168.1.10 8.8.8.8 54321 53",
            ],
        )
        # Put the private IP in the cache to prove it's skipped
        cache_with_private = {
            "ip": {"192.168.1.10", "8.8.8.8"},
            "domain": set(),
        }
        with patch("lookup.get_ioc_cache", return_value=cache_with_private):
            hits = scan_firewall_logs()
        # 8.8.8.8 should hit (it's public and in cache), but 192.168.1.10 should not
        src_hits = [h for h in hits if h["direction"] == "inbound" and h["ioc"] == "192.168.1.10"]
        assert len(src_hits) == 0


# ===========================================================================
#   Task 2 — DNS cache scanner (7 tests)
# ===========================================================================


class TestDNSCacheScanner:
    def _mock_ps_result(self, stdout="", returncode=0, stderr=""):
        """Create a mock subprocess.run result for PowerShell DNS queries."""
        mock_result = MagicMock()
        mock_result.stdout = stdout
        mock_result.stderr = stderr
        mock_result.returncode = returncode
        return mock_result

    def test_detects_malicious_domain(self, tmp_path):
        """A domain in the cache that matches a threat feed should be a hit."""
        ps_output = "evil.ru\nsafe-site.com\n"
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("scanner.subprocess.run", return_value=self._mock_ps_result(ps_output)),
        ):
            hits = scan_dns_cache()
        assert len(hits) == 1
        assert hits[0]["ioc"] == "evil.ru"

    def test_clean_domains_no_hits(self, tmp_path):
        """Domains not in the threat cache should produce no hits."""
        ps_output = "safe-site.com\nanother-clean.org\n"
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("scanner.subprocess.run", return_value=self._mock_ps_result(ps_output)),
        ):
            hits = scan_dns_cache()
        assert hits == []

    def test_whitelisted_domain_skipped(self, tmp_path):
        """Whitelisted domains (e.g. microsoft.com) should be skipped."""
        ps_output = "microsoft.com\nlogin.microsoft.com\nevil.ru\n"
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("scanner.subprocess.run", return_value=self._mock_ps_result(ps_output)),
        ):
            hits = scan_dns_cache()
        # Only evil.ru should be a hit; microsoft.com variants are whitelisted
        assert len(hits) == 1
        assert hits[0]["ioc"] == "evil.ru"

    def test_empty_cache_returns_empty(self, tmp_path):
        """When PowerShell returns no domains, result should be empty."""
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("scanner.subprocess.run", return_value=self._mock_ps_result("")),
        ):
            hits = scan_dns_cache()
        assert hits == []

    def test_powershell_error_returns_empty(self, tmp_path):
        """If PowerShell raises an exception, return empty list gracefully."""
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("scanner.subprocess.run", side_effect=FileNotFoundError("powershell not found")),
        ):
            hits = scan_dns_cache()
        assert hits == []

    def test_callback_receives_messages(self, tmp_path):
        """The callback should receive status messages during the scan."""
        ps_output = "evil.ru\n"
        messages = []
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("scanner.subprocess.run", return_value=self._mock_ps_result(ps_output)),
        ):
            scan_dns_cache(callback=messages.append)
        assert len(messages) > 0
        assert any("[HIT]" in m for m in messages)

    def test_deduplicates_domains(self, tmp_path):
        """Duplicate domains in PowerShell output should produce only one hit."""
        ps_output = "evil.ru\nevil.ru\nevil.ru\n"
        with (
            patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE),
            patch("scanner.subprocess.run", return_value=self._mock_ps_result(ps_output)),
        ):
            hits = scan_dns_cache()
        assert len(hits) == 1


# ===========================================================================
#   Task 3 — Email header analyser (10 tests)
# ===========================================================================


class TestEmailHeaderAnalyser:
    CLEAN_HEADERS = (
        "Received: from mail.safe.com (1.2.3.4) by mx.example.com\n"
        "From: user@safe.com\n"
        "Reply-To: user@safe.com\n"
        "Subject: Hello\n"
        "Message-ID: <abc@safe.com>\n"
    )

    MALICIOUS_IP_HEADERS = (
        "Received: from relay.unknown.com (185.234.1.1) by mx.example.com\nFrom: user@unknown.com\nSubject: Important\n"
    )

    MALICIOUS_DOMAIN_HEADERS = (
        "Received: from evil.ru (1.2.3.4) by mx.example.com\nFrom: user@evil.ru\nSubject: Click here\n"
    )

    MISMATCH_HEADERS = (
        "Received: from mail.legit.com (1.2.3.4) by mx.example.com\n"
        "From: boss@company.com\n"
        "Reply-To: attacker@phishing.net\n"
        "Subject: Urgent wire transfer\n"
    )

    def test_clean_headers_verdict(self, tmp_path):
        """Clean headers should produce a 'No known threats' verdict."""
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            report = analyse_email_headers(self.CLEAN_HEADERS)
        assert "No known threats" in report

    def test_malicious_ip_detected(self, tmp_path):
        """A malicious IP in a Received: header should be flagged."""
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            report = analyse_email_headers(self.MALICIOUS_IP_HEADERS)
        assert "185.234.1.1" in report
        assert "MALICIOUS" in report

    def test_malicious_domain_detected(self, tmp_path):
        """A malicious domain in a Received: header should be flagged."""
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            report = analyse_email_headers(self.MALICIOUS_DOMAIN_HEADERS)
        assert "MALICIOUS" in report
        assert "evil.ru" in report

    def test_from_reply_to_mismatch(self, tmp_path):
        """Mismatched From and Reply-To domains should trigger a warning."""
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            report = analyse_email_headers(self.MISMATCH_HEADERS)
        assert "From != Reply-To" in report or "WARNING" in report

    def test_private_ips_excluded(self, tmp_path):
        """Private IPs (10.x, 192.168.x) in Received: headers should be excluded."""
        headers = "Received: from internal (192.168.1.1) by gateway (10.0.0.1)\nSubject: Test\n"
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            report = analyse_email_headers(headers)
        # Private IPs should not appear in the report IP list
        assert "192.168.1.1" not in report
        assert "10.0.0.1" not in report
        assert "IPs found     : 0" in report

    def test_ips_only_from_received_headers(self, tmp_path):
        """IPs in Message-ID or other non-Received headers should be ignored."""
        headers = (
            "Received: from relay.safe.com (1.2.3.4) by mx.example.com\n"
            "Message-ID: <185.234.1.1.abc@example.com>\n"
            "X-Custom: 5.5.5.5\n"
            "Subject: Test\n"
        )
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            report = analyse_email_headers(headers)
        # 185.234.1.1 is in Message-ID (not Received:) so should NOT be flagged
        # 5.5.5.5 is in X-Custom (not Received:) so should NOT be flagged
        # Only 1.2.3.4 from the Received: line should appear
        assert "185.234.1.1" not in report or "MALICIOUS" not in report.split("185.234.1.1")[0].split("\n")[-1]
        # More direct: the only IP found should be 1.2.3.4
        assert "IPs found     : 1" in report

    def test_empty_headers_no_crash(self, tmp_path):
        """Empty header text should not crash and should return a report."""
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            report = analyse_email_headers("")
        assert "PhantomEye" in report
        assert "VERDICT" in report

    def test_report_format(self, tmp_path):
        """Report should contain expected structural elements."""
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            report = analyse_email_headers(self.CLEAN_HEADERS)
        assert "PhantomEye" in report
        assert "Email Header Analysis" in report
        assert "IPs found" in report
        assert "Domains found" in report
        assert "VERDICT" in report
        # Should have the separator lines
        assert "=" * 60 in report
        assert "-" * 60 in report

    def test_whitelisted_domain_excluded(self, tmp_path):
        """Whitelisted domains (e.g. google.com) should not appear as hits."""
        headers = (
            "Received: from mail.google.com (142.250.80.5) by mx.example.com\nFrom: user@google.com\nSubject: Test\n"
        )
        with patch(
            "lookup.get_ioc_cache",
            return_value={
                "ip": set(),
                "domain": {"google.com"},  # even if in cache, whitelist should skip
            },
        ):
            report = analyse_email_headers(headers)
        # google.com is whitelisted so should not appear as MALICIOUS
        assert "MALICIOUS" not in report or "google.com" not in report

    def test_multiple_received_headers(self, tmp_path):
        """IPs from multiple Received: headers should all be checked."""
        headers = (
            "Received: from hop1.example.com (1.2.3.4) by hop2.example.com\n"
            "Received: from hop2.example.com (185.234.1.1) by final.example.com\n"
            "From: user@example.com\n"
            "Subject: Test\n"
        )
        with patch("lookup.get_ioc_cache", return_value=SAMPLE_CACHE):
            report = analyse_email_headers(headers)
        assert "IPs found     : 2" in report
        assert "185.234.1.1" in report
        assert "MALICIOUS" in report
