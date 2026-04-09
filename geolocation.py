# =============================================================================
#   geolocation.py — PhantomEye v1.4
#   Red Parrot Accounting Ltd
#
#   IP geolocation via ip-api.com (free, no API key required).
#   Returns country, city, ISP, org, and AS number for a given IP.
# =============================================================================

import json
import urllib.error
import urllib.request

from logger import log

_GEO_API = "http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as"
_TIMEOUT = 5


def geolocate_ip(ip: str) -> dict | None:
    """
    Look up geolocation for an IP address via ip-api.com.
    Returns dict with keys: country, city, isp, org, as_number.
    Returns None on failure.
    """
    try:
        url = _GEO_API.format(ip=ip)
        req = urllib.request.Request(url, headers={"User-Agent": "PhantomEye/1.5.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") != "success":
            log.debug("Geolocation failed for %s: %s", ip, data.get("message", "unknown"))
            return None
        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", "Unknown"),
            "as_number": data.get("as", "Unknown"),
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        log.debug("Geolocation request failed for %s: %s", ip, e)
        return None
