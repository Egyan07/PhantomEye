# =============================================================================
#   utils.py — PhantomEye v1.1
#   Red Parrot Accounting Ltd
#
#   Pure utility functions: IP/domain validation, private-range detection,
#   URL parsing, whitelist checks. No side effects.
# =============================================================================

import re
from urllib.parse import urlparse

from config import WHITELIST_IPS, WHITELIST_DOMAINS


# ---------------------------------------------------------------------------
#   IP helpers
# ---------------------------------------------------------------------------

def is_valid_ipv4(ip: str) -> bool:
    """Return True for a syntactically valid IPv4 address."""
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


def is_valid_ipv6(ip: str) -> bool:
    """Return True for a syntactically valid IPv6 address (basic check)."""
    # Covers full, compressed, and mixed notations well enough for feed parsing
    ip = ip.strip()
    if ":" not in ip:
        return False
    # Allow up to 8 groups of hex digits, allowing :: compression
    pattern = re.compile(
        r"^("
        r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"          # full
        r"|([0-9a-fA-F]{1,4}:){1,7}:"                        # trailing ::
        r"|:([:[0-9a-fA-F]{1,4}]){1,7}"                      # leading ::
        r"|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})"     # ::middle
        r"|::([fF]{4}(:0{1,4})?:)?"
          r"((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}"
          r"(25[0-5]|(2[0-4]|1?[0-9])?[0-9])"                # ::ffff:IPv4
        r"|([0-9a-fA-F]{1,4}:){1,4}:"
          r"((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}"
          r"(25[0-5]|(2[0-4]|1?[0-9])?[0-9])"                # IPv4-mapped
        r"|::"                                                 # unspecified
        r")$"
    )
    return bool(pattern.match(ip))


def is_valid_ip(ip: str) -> bool:
    """Return True for any valid IPv4 or IPv6 address."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_private_ip(ip: str) -> bool:
    """
    Return True if the IPv4 address is in a private/reserved range.
    IPv6 loopback (::1) and link-local (fe80::) are also caught.
    """
    ip = ip.strip()

    # IPv6 special ranges
    if ":" in ip:
        lc = ip.lower()
        if lc == "::1":
            return True
        if lc.startswith("fe80") or lc.startswith("fc") or lc.startswith("fd"):
            return True
        return False

    try:
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        if a == 10:                        return True   # 10.0.0.0/8
        if a == 127:                       return True   # loopback
        if a == 172 and 16 <= b <= 31:     return True   # 172.16–31.x.x
        if a == 192 and b == 168:          return True   # 192.168.x.x
        if a == 169 and b == 254:          return True   # link-local
        if a == 0:                         return True   # 0.x.x.x
        if a == 255:                       return True   # broadcast
    except Exception:
        pass
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
    # No label longer than 63 chars (RFC 1035)
    if any(len(lbl) > 63 or len(lbl) == 0 for lbl in labels):
        return False
    return True


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
        host   = (parsed.hostname or "").lower()
        # Strip www. only — keep other subdomains for lookup matching
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
