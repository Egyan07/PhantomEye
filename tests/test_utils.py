# =============================================================================
#   tests/test_utils.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Unit tests for utils.py — IP/domain validation, private range detection,
#   URL extraction, and whitelist logic.
#   Run with: pytest tests/test_utils.py -v
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
#   Helpers to avoid importing config (which creates log dirs)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_config(tmp_path):
    """Provide minimal config so logger.py doesn't write to C:\\SecurityLogs."""
    with patch.dict("sys.modules", {}):
        with (
            patch("config.LOG_DIR", str(tmp_path / "logs")),
            patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
            patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
            patch("config.WHITELIST_IPS", ["127.0.0.1", "0.0.0.0"]),
            patch("config.WHITELIST_DOMAINS", ["microsoft.com", "google.com"]),
        ):
            os.makedirs(str(tmp_path / "logs"), exist_ok=True)
            os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
            yield


from utils import (
    extract_domain_from_url,
    is_private_ip,
    is_valid_domain,
    is_valid_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    is_whitelisted,
)

# ---------------------------------------------------------------------------
#   IPv4
# ---------------------------------------------------------------------------


class TestIsValidIPv4:
    def test_valid(self):
        assert is_valid_ipv4("1.2.3.4")
        assert is_valid_ipv4("255.255.255.255")
        assert is_valid_ipv4("0.0.0.0")

    def test_invalid_out_of_range(self):
        assert not is_valid_ipv4("256.0.0.1")
        assert not is_valid_ipv4("1.2.3.999")

    def test_invalid_format(self):
        assert not is_valid_ipv4("not-an-ip")
        assert not is_valid_ipv4("1.2.3")
        assert not is_valid_ipv4("1.2.3.4.5")
        assert not is_valid_ipv4("")

    def test_ipv6_rejected(self):
        assert not is_valid_ipv4("::1")
        assert not is_valid_ipv4("2001:db8::1")


# ---------------------------------------------------------------------------
#   IPv6
# ---------------------------------------------------------------------------


class TestIsValidIPv6:
    def test_full(self):
        assert is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_compressed(self):
        assert is_valid_ipv6("::1")
        assert is_valid_ipv6("fe80::1")
        assert is_valid_ipv6("2001:db8::1")
        assert is_valid_ipv6("::")

    def test_ipv4_mapped(self):
        assert is_valid_ipv6("::ffff:192.0.2.1")

    def test_invalid(self):
        assert not is_valid_ipv6("192.168.1.1")
        assert not is_valid_ipv6("not-ipv6")
        assert not is_valid_ipv6("")
        assert not is_valid_ipv6("gggg::1")

    def test_trailing_colon_compressed(self):
        # e.g. "2001:db8::" — trailing double-colon
        assert is_valid_ipv6("2001:db8::")


# ---------------------------------------------------------------------------
#   is_valid_ip (combined)
# ---------------------------------------------------------------------------


class TestIsValidIP:
    def test_ipv4(self):
        assert is_valid_ip("8.8.8.8")

    def test_ipv6(self):
        assert is_valid_ip("::1")
        assert is_valid_ip("2001:db8::1")

    def test_invalid(self):
        assert not is_valid_ip("evil.com")
        assert not is_valid_ip("")


# ---------------------------------------------------------------------------
#   Private IP
# ---------------------------------------------------------------------------


class TestIsPrivateIP:
    def test_loopback(self):
        assert is_private_ip("127.0.0.1")
        assert is_private_ip("::1")

    def test_rfc1918(self):
        assert is_private_ip("10.0.0.1")
        assert is_private_ip("172.16.0.1")
        assert is_private_ip("172.31.255.255")
        assert is_private_ip("192.168.1.100")

    def test_link_local(self):
        assert is_private_ip("169.254.1.1")
        assert is_private_ip("fe80::1")

    def test_unspecified(self):
        assert is_private_ip("0.0.0.0")

    def test_broadcast(self):
        assert is_private_ip("255.255.255.255")

    def test_public(self):
        assert not is_private_ip("8.8.8.8")
        assert not is_private_ip("185.234.1.1")
        assert not is_private_ip("1.1.1.1")

    def test_ipv6_public(self):
        # 2001:db8::/32 is the documentation range — Python's ipaddress marks it
        # as reserved, which is correct (it should never appear in live traffic).
        # Use a real public IPv6 address for the "not private" assertion.
        assert not is_private_ip("2606:4700:4700::1111")  # Cloudflare public DNS


# ---------------------------------------------------------------------------
#   Domain validation
# ---------------------------------------------------------------------------


class TestIsValidDomain:
    def test_valid(self):
        assert is_valid_domain("evil.ru")
        assert is_valid_domain("sub.evil.ru")
        assert is_valid_domain("xn--nxasmq6b.com")  # punycode

    def test_too_short(self):
        assert not is_valid_domain("a.b")  # TLD only 1 char
        assert not is_valid_domain("x.y")

    def test_single_label(self):
        assert not is_valid_domain("localhost")

    def test_empty(self):
        assert not is_valid_domain("")

    def test_invalid_chars(self):
        assert not is_valid_domain("evil domain.com")
        assert not is_valid_domain("evil@domain.com")

    def test_too_long_label(self):
        long_label = "a" * 64
        assert not is_valid_domain(f"{long_label}.com")

    def test_empty_label(self):
        assert not is_valid_domain("evil..com")


# ---------------------------------------------------------------------------
#   URL extraction
# ---------------------------------------------------------------------------


class TestExtractDomainFromUrl:
    def test_simple_https(self):
        assert extract_domain_from_url("https://evil.ru/path") == "evil.ru"

    def test_strips_www(self):
        assert extract_domain_from_url("http://www.evil.ru") == "evil.ru"

    def test_preserves_subdomain(self):
        assert extract_domain_from_url("https://phish.login.evil.ru") == "phish.login.evil.ru"

    def test_no_scheme(self):
        assert extract_domain_from_url("evil.ru/malware.exe") == "evil.ru"

    def test_empty(self):
        assert extract_domain_from_url("") == ""

    def test_garbage(self):
        result = extract_domain_from_url("not a url at all !!!")
        # Should not crash — may return empty string
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
#   Whitelist
# ---------------------------------------------------------------------------


class TestIsWhitelisted:
    def test_private_ip_always_whitelisted(self):
        assert is_whitelisted("192.168.1.1", "ip")
        assert is_whitelisted("10.0.0.1", "ip")

    def test_explicit_whitelist_ip(self):
        assert is_whitelisted("127.0.0.1", "ip")

    def test_public_ip_not_whitelisted(self):
        assert not is_whitelisted("8.8.8.8", "ip")

    def test_whitelisted_domain_exact(self):
        assert is_whitelisted("microsoft.com", "domain")
        assert is_whitelisted("google.com", "domain")

    def test_whitelisted_domain_subdomain(self):
        assert is_whitelisted("login.microsoft.com", "domain")
        assert is_whitelisted("mail.google.com", "domain")

    def test_not_whitelisted_domain(self):
        assert not is_whitelisted("evil.ru", "domain")
        assert not is_whitelisted("fakemicrosoft.com", "domain")

    def test_domain_prefix_not_whitelisted(self):
        # "evilmicrosoft.com" should NOT match "microsoft.com"
        assert not is_whitelisted("evilmicrosoft.com", "domain")
