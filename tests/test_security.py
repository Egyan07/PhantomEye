# =============================================================================
#   tests/test_security.py — PhantomEye
#   Red Parrot Accounting Ltd
#
#   Input-validation security tests: path traversal, injection attempts,
#   oversized input, and email header injection.
#   Run with: pytest tests/test_security.py -v
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
#   Shared fixture — same pattern used by test_utils.py / test_scanner.py
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_config(tmp_path):
    """Provide minimal config so logger.py doesn't write to C:\\SecurityLogs."""
    with (
        patch("config.LOG_DIR", str(tmp_path / "logs")),
        patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
        patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
        patch("config.DB_PATH", str(tmp_path / "phantom_eye.db")),
        patch("config.FIREWALL_LOG", str(tmp_path / "pfirewall.log")),
        patch("config.FIREWALL_LOG_DAYS", 1),
        patch("config.ADMIN_PC", "TESTPC"),
        patch("config.ALERT_DEDUPE_HOURS", 24),
        patch("config.EMAIL_ENABLED", False),
        patch("config.WHITELIST_IPS", ["127.0.0.1", "0.0.0.0"]),
        patch("config.WHITELIST_DOMAINS", ["microsoft.com", "google.com"]),
    ):
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield


from scanner import analyse_email_headers
from utils import (
    extract_domain_from_url,
    is_valid_domain,
    is_valid_ip,
    is_whitelisted,
)

# Cache fixtures used by email header tests
EMPTY_CACHE = {"ip": set(), "domain": set()}
SAMPLE_CACHE = {
    "ip": {"185.234.1.1", "5.5.5.5"},
    "domain": {"evil.ru", "malware.bad.com"},
}


# ===========================================================================
#   Path Traversal (5 tests)
# ===========================================================================


class TestPathTraversal:
    def test_dotdot_in_domain(self):
        """Path traversal sequences must be rejected as invalid domains."""
        assert not is_valid_domain("../../etc/passwd")

    def test_null_byte_in_domain(self):
        """Null bytes embedded in a domain string must be rejected."""
        assert not is_valid_domain("evil.com\x00.txt")

    def test_backslash_in_domain(self):
        """Backslash-based path traversal must be rejected."""
        assert not is_valid_domain("evil\\..\\windows")

    def test_dotdot_ip_rejected(self):
        """Path traversal strings are not valid IP addresses."""
        assert not is_valid_ip("../../../etc")

    def test_url_with_traversal(self):
        """extract_domain_from_url should return only the hostname, not the path."""
        result = extract_domain_from_url("http://evil.com/../../etc/passwd")
        assert result == "evil.com"


# ===========================================================================
#   Injection Attempts (5 tests)
# ===========================================================================


class TestInjectionAttempts:
    def test_sql_in_domain(self):
        """SQL injection payloads must be rejected as invalid domains."""
        assert not is_valid_domain("'; DROP TABLE iocs;--")

    def test_html_in_domain(self):
        """HTML/script injection payloads must be rejected."""
        assert not is_valid_domain("<script>alert(1)</script>")

    def test_newline_injection_domain(self):
        """Newline characters in a domain string must be rejected."""
        assert not is_valid_domain("evil.com\ninjected")

    def test_very_long_domain_rejected(self):
        """Extremely long domains (>253 chars) must be rejected."""
        assert not is_valid_domain("a" * 300 + ".com")

    def test_unicode_domain_rejected(self):
        """Non-ASCII characters must be rejected by the domain regex."""
        assert not is_valid_domain("ëvîl.cöm")


# ===========================================================================
#   Oversized Input (4 tests)
# ===========================================================================


class TestOversizedInput:
    def test_huge_ip_string(self):
        """A 10 000-char string must not crash is_valid_ip."""
        assert not is_valid_ip("1" * 10000)

    def test_huge_domain_string(self):
        """A 10 000-char string must not crash is_valid_domain."""
        assert not is_valid_domain("a" * 10000)

    def test_empty_strings_safe(self):
        """Empty strings should safely return False for all validators."""
        assert not is_valid_ip("")
        assert not is_valid_domain("")
        assert not is_whitelisted("", "ip")

    def test_whitespace_only(self):
        """Whitespace-only strings should safely return False."""
        assert not is_valid_ip("   ")
        assert not is_valid_domain("   ")


# ===========================================================================
#   Email Header Injection (4 tests)
# ===========================================================================


class TestEmailHeaderInjection:
    def test_header_with_null_bytes(self):
        """Null bytes in email headers must not crash the analyser."""
        headers = "From: test\x00@evil.com\nReceived: from x (1.2.3.4)"
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            report = analyse_email_headers(headers)
        assert isinstance(report, str)

    def test_header_with_huge_input(self):
        """A 100 000-char header must not crash and must return a string."""
        headers = "Received: " + "A" * 100000
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            report = analyse_email_headers(headers)
        assert isinstance(report, str)

    def test_header_with_binary(self):
        """Binary-like content (all byte values) must not crash the analyser."""
        headers = bytes(range(256)).decode("utf-8", errors="replace")
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            report = analyse_email_headers(headers)
        assert isinstance(report, str)

    def test_header_sql_injection(self):
        """SQL injection in a Received: header must not crash the analyser."""
        headers = "Received: from '; DROP TABLE alerts;-- (1.2.3.4)"
        with patch("lookup.get_ioc_cache", return_value=EMPTY_CACHE):
            report = analyse_email_headers(headers)
        assert isinstance(report, str)
