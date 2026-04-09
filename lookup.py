# =============================================================================
#   lookup.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   IOC lookup engine.
#
#   FIXES v1.2:
#   - total_iocs and feeds_last_updated now come from the in-memory
#     _meta_cache in feeds.py — zero extra DB connections per lookup.
#   - Empty-value input now returns an explicit error dict instead of a
#     misleading "Clean" result.
#   - lookup_ioc() exception on DB metadata fetch is now logged at DEBUG.
# =============================================================================

import sqlite3

from config import DB_PATH
from feeds import feeds_loaded, get_ioc_cache, get_last_feed_time
from utils import is_valid_ip, is_whitelisted


def is_ioc_known(value: str, ioc_type: str) -> bool:
    """
    Fast O(1) check: is this value in the threat database?
    Uses the in-memory cache — no DB I/O.
    """
    value = value.strip().lower()
    cache = get_ioc_cache()
    if ioc_type not in cache:
        return False

    if value in cache[ioc_type]:
        return True

    # For domains: walk up subdomain hierarchy
    # e.g. m.evil.ru → check evil.ru (skip bare TLD)
    if ioc_type == "domain":
        parts = value.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in cache["domain"]:
                return True

    return False


def lookup_ioc(value: str, ioc_type: str = None) -> dict:
    """
    Full lookup: returns a result dict with match metadata.

    FIX: empty value returns error dict immediately.
    FIX: total_iocs / feeds_last_updated come from meta cache (no DB).

    Returns:
        {
            found               (bool),
            value               (str),
            type                (str),
            matches             (list[dict]),
            total_iocs          (int),
            feeds_last_updated  (str),
            zero_feeds_warning  (bool),
            error               (str | None),
        }
    """
    value = value.strip().lower()

    # Auto-strip full URLs to hostname
    if value.startswith("http"):
        from utils import extract_domain_from_url

        extracted = extract_domain_from_url(value)
        value = extracted if extracted else (value.replace("https://", "").replace("http://", "").split("/")[0])

    # FIX: reject empty input explicitly
    if not value:
        return {
            "found": False,
            "value": "",
            "type": "unknown",
            "matches": [],
            "total_iocs": feeds_loaded(),
            "feeds_last_updated": get_last_feed_time(),
            "zero_feeds_warning": feeds_loaded() == 0,
            "error": "Empty query — please enter an IP address or domain.",
        }

    if ioc_type is None:
        ioc_type = "ip" if is_valid_ip(value) else "domain"

    total_iocs = feeds_loaded()
    result = {
        "found": False,
        "value": value,
        "type": ioc_type,
        "matches": [],
        "total_iocs": total_iocs,
        "feeds_last_updated": get_last_feed_time(),
        "zero_feeds_warning": total_iocs == 0,
        "error": None,
    }

    if not is_ioc_known(value, ioc_type):
        return result

    result["found"] = True

    # Fetch metadata from DB only on a confirmed hit (one query)
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute(
            """
            SELECT type, value, threat_type, source, first_added, last_updated
            FROM iocs WHERE value = ? AND type = ?
        """,
            (value, ioc_type),
        )
        row = cur.fetchone()
        if row:
            result["matches"].append(
                {
                    "threat_type": row[2],
                    "source": row[3],
                    "first_added": row[4],
                    "last_updated": row[5],
                }
            )

        # Subdomain parent match
        if ioc_type == "domain" and not result["matches"]:
            parts = value.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                cur.execute(
                    """
                    SELECT type, value, threat_type, source
                    FROM iocs WHERE value = ? AND type = 'domain'
                """,
                    (parent,),
                )
                parent_row = cur.fetchone()
                if parent_row:
                    result["subdomain_match"] = parent
                    result["matches"].append(
                        {
                            "threat_type": parent_row[2],
                            "source": parent_row[3],
                            "note": f"Subdomain of known malicious domain: {parent}",
                        }
                    )
                    break

        conn.close()
    except Exception as e:
        from logger import log

        log.debug("Could not fetch IOC metadata for %s: %s", value, e)

    return result


def format_lookup_result(result: dict) -> str:
    """Format a lookup result dict as a human-readable string."""
    lines = []
    lines.append("=" * 55)
    lines.append("  PhantomEye Lookup Result")
    lines.append("=" * 55)

    if result.get("error"):
        lines.append(f"  ERROR: {result['error']}")
        lines.append("=" * 55)
        return "\n".join(lines)

    lines.append(f"  Query     : {result['value']}")
    lines.append(f"  Type      : {result['type'].upper()}")
    lines.append(f"  DB Size   : {result.get('total_iocs', 0):,} IOCs")
    lines.append(f"  Feeds     : {result.get('feeds_last_updated', 'Unknown')}")

    if result.get("zero_feeds_warning"):
        lines.append("")
        lines.append("  WARNING: No feeds loaded yet.")
        lines.append("  All results will show Clean until feeds are updated.")
        lines.append("  Click 'Update Feeds' in the Dashboard first.")

    lines.append("-" * 55)

    if result["found"]:
        lines.append("  VERDICT   : MALICIOUS — FOUND IN THREAT DATABASE")
        lines.append("")
        for i, match in enumerate(result["matches"], 1):
            lines.append(f"  Match #{i}:")
            lines.append(f"    Threat type : {match.get('threat_type', 'Unknown').upper()}")
            lines.append(f"    Feed source : {match.get('source', 'Unknown')}")
            if "note" in match:
                lines.append(f"    Note        : {match['note']}")
            if "first_added" in match:
                lines.append(f"    First seen  : {match.get('first_added', '')}")
        lines.append("")
        lines.append("  ACTION: Block immediately if this is an active connection.")
    else:
        if is_whitelisted(result["value"], result["type"]):
            lines.append("  VERDICT   : WHITELISTED — Known safe")
        else:
            lines.append("  VERDICT   : CLEAN — Not found in any threat feed")
            lines.append("  Note: Absence from feeds does not guarantee safety.")
            lines.append("  New/unknown threats may not yet appear in feeds.")

    lines.append("=" * 55)
    return "\n".join(lines)
