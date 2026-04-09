# =============================================================================
#   utils.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Pure utility functions: IP/domain validation, private-range detection,
#   URL parsing, whitelist checks. No side effects.
#
#   FIX v1.2: Replaced hand-rolled IPv6 regex (had character-class typo)
#             with Python's stdlib ipaddress module — handles every RFC-
#             compliant IPv4/IPv6 address including edge cases.
#             is_private_ip now correctly catches multicast, reserved, and
#             unspecified ranges that the old manual checks missed.
# =============================================================================

import ipaddress
import re
from urllib.parse import urlparse

from config import WHITELIST_DOMAINS, WHITELIST_IPS

# ---------------------------------------------------------------------------
#   IP helpers  (stdlib ipaddress — correct, fast, no regex needed)
# ---------------------------------------------------------------------------


def is_valid_ipv4(ip: str) -> bool:
    """Return True for a syntactically valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip.strip())
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Return True for a syntactically valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip.strip())
        return True
    except ValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """Return True for any valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    Return True if the address is private, loopback, link-local, multicast,
    reserved, or unspecified — i.e. should never appear in public threat feeds.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_unspecified
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------
#   Domain helpers
# ---------------------------------------------------------------------------


def is_valid_domain(domain: str) -> bool:
    """
    Return True for a syntactically plausible domain name.
    Requires at least two labels and a TLD of 2+ characters.
    """
    domain = domain.strip().lower()
    if len(domain) < 4 or len(domain) > 253:
        return False
    if not re.match(r"^[a-z0-9.\-]+$", domain):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if len(tld) < 2:
        return False
    # No label longer than 63 chars (RFC 1035), no empty labels
    return not any(len(lbl) > 63 or len(lbl) == 0 for lbl in labels)


def extract_domain_from_url(url: str) -> str:
    """
    Extract the registered hostname from a URL string.
    Strips www. but preserves other subdomains so that the subdomain
    matching in lookup.py can walk up to the parent domain.
    Returns empty string on failure.
    """
    try:
        url = url.strip()
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        host = re.sub(r"^www\.", "", host)
        return host
    except Exception:
        return ""


# ---------------------------------------------------------------------------
#   Whitelist
# ---------------------------------------------------------------------------


def is_whitelisted(value: str, ioc_type: str) -> bool:
    """Return True if an IP or domain should be ignored."""
    value = value.lower().strip()
    if ioc_type == "ip":
        if is_private_ip(value):
            return True
        return value in {w.lower() for w in WHITELIST_IPS}
    elif ioc_type == "domain":
        for wl in WHITELIST_DOMAINS:
            wl = wl.lower()
            if value == wl or value.endswith("." + wl):
                return True
    return False
