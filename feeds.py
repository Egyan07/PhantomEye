# =============================================================================
#   feeds.py — PhantomEye v1.1
#   Red Parrot Accounting Ltd
#
#   Threat feed download, parsing, and IOC database ingestion.
#   Also manages the in-memory IOC set used for fast O(1) lookups.
# =============================================================================

import os
import re
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime

from config import DB_PATH, FEEDS_DIR, THREAT_FEEDS
from logger import log
from utils import (
    is_valid_ip, is_valid_ipv4, is_private_ip,
    is_valid_domain, is_whitelisted,
    extract_domain_from_url,
)

# ---------------------------------------------------------------------------
#   In-memory IOC sets — loaded once at startup, refreshed after feed update
#   Structure: {"ip": set(), "domain": set()}
#   Enables O(1) lookup instead of a DB round-trip per IOC checked.
# ---------------------------------------------------------------------------
_ioc_cache: dict[str, set] = {"ip": set(), "domain": set()}


def load_ioc_cache() -> dict[str, set]:
    """
    Load all IOCs from the database into memory.
    Call this once at startup and after every feed update.
    Returns the populated cache dict.
    """
    global _ioc_cache
    _ioc_cache = {"ip": set(), "domain": set()}
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("SELECT type, value FROM iocs")
        for ioc_type, value in cur.fetchall():
            if ioc_type in _ioc_cache:
                _ioc_cache[ioc_type].add(value.lower())
        conn.close()
        log.info(
            "IOC cache loaded: %d IPs, %d domains",
            len(_ioc_cache["ip"]), len(_ioc_cache["domain"])
        )
    except Exception as e:
        log.warning("Could not load IOC cache: %s", e)
    return _ioc_cache


def get_ioc_cache() -> dict[str, set]:
    """Return the current in-memory IOC cache (may be empty if not yet loaded)."""
    return _ioc_cache


def feeds_loaded() -> int:
    """Return total number of IOCs currently in the database (0 = feeds never run)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM iocs")
        count = cur.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


# ---------------------------------------------------------------------------
#   Download
# ---------------------------------------------------------------------------

def download_feed(feed_name: str, feed_config: dict) -> str | None:
    """
    Download a single threat feed and return raw content as a string.
    Falls back to the cached file on download failure.
    """
    url      = feed_config["url"]
    filepath = os.path.join(FEEDS_DIR, f"{feed_name}.txt")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PhantomEye/1.1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return content
    except urllib.error.URLError as e:
        log.warning("Feed download failed [%s]: %s", feed_name, e)
        if os.path.exists(filepath):
            log.info("Using cached feed for: %s", feed_name)
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()
        return None


# ---------------------------------------------------------------------------
#   Parsing
# ---------------------------------------------------------------------------

# Maps feed names to a human-readable threat category
_THREAT_MAP = {
    "feodo_ips":        "c2",
    "emerging_threats": "compromised",
    "cins_score":       "bad_actor",
    "abuse_ssl":        "malware",
    "urlhaus_domains":  "malware",
    "openphish":        "phishing",
    "botvrij_domains":  "malware",
    "botvrij_ips":      "malware",
}


def parse_feed(content: str, feed_name: str, feed_config: dict) -> list[str]:
    """
    Parse feed content into a deduplicated list of IOC values.

    Supported formats: plain_ip, feodo_csv, abuse_ssl_csv,
                       url_extract, plain_domain.

    BUG FIX: feodo_csv and abuse_ssl_csv now validate against column
    headers when present so format changes don't silently skip everything.
    """
    iocs     = []
    fmt      = feed_config["format"]
    ioc_type = feed_config["type"]
    lines    = content.splitlines()

    # For CSV feeds: detect column index from header row dynamically
    ip_col_index = _detect_ip_column(lines, fmt)

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        value = None

        if fmt == "plain_ip":
            candidate = line.split()[0].split(",")[0]
            if is_valid_ip(candidate) and not is_private_ip(candidate):
                value = candidate

        elif fmt in ("feodo_csv", "abuse_ssl_csv"):
            parts = line.split(",")
            if len(parts) > ip_col_index:
                candidate = parts[ip_col_index].strip().strip('"')
                if is_valid_ip(candidate) and not is_private_ip(candidate):
                    value = candidate

        elif fmt == "url_extract":
            domain = extract_domain_from_url(line)
            if domain and is_valid_domain(domain) and not is_whitelisted(domain, "domain"):
                value = domain

        elif fmt == "plain_domain":
            candidate = line.split()[0].lower().strip(".")
            if is_valid_domain(candidate) and not is_whitelisted(candidate, "domain"):
                value = candidate

        if value and not is_whitelisted(value, ioc_type):
            iocs.append(value.lower())

    return list(set(iocs))


def _detect_ip_column(lines: list[str], fmt: str) -> int:
    """
    Find the column index that contains the IP in a CSV feed by inspecting
    the header row. Falls back to the v1.0 hardcoded defaults if no header
    is found, so existing known-good feeds continue to work.
    """
    defaults = {"feodo_csv": 1, "abuse_ssl_csv": 1}
    for line in lines[:5]:
        line = line.strip()
        if not line or not line.startswith("#"):
            continue
        # Header lines look like "# first_seen_utc,dst_ip,dst_port,..."
        header = line.lstrip("# ").lower()
        cols   = [c.strip() for c in header.split(",")]
        for i, col in enumerate(cols):
            if col in ("dst_ip", "dstip", "ip", "ipaddress", "ip_address"):
                return i
    return defaults.get(fmt, 1)


# ---------------------------------------------------------------------------
#   Ingestion
# ---------------------------------------------------------------------------

def update_feeds(callback=None) -> int:
    """
    Download all threat feeds, parse them, and upsert IOCs into the database.
    Reloads the in-memory IOC cache when done.

    callback: optional callable(str) for GUI progress messages.
    Returns total IOC count in database after update.
    """
    log.info("=" * 60)
    log.info("PhantomEye v1.1 — Updating threat feeds")
    log.info("=" * 60)

    conn      = sqlite3.connect(DB_PATH)
    cur       = conn.cursor()
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_new = 0

    for feed_name, feed_config in THREAT_FEEDS.items():
        label = feed_config["label"]
        if callback:
            callback(f"Downloading: {label}...")
        log.info("Downloading: %s", label)

        content = download_feed(feed_name, feed_config)
        if content is None:
            cur.execute("""
                INSERT OR REPLACE INTO feed_status
                    (feed_name, label, last_updated, ioc_count, status)
                VALUES (?, ?, ?, 0, 'FAILED')
            """, (feed_name, label, now))
            conn.commit()
            if callback:
                callback(f"  {label}: FAILED (no cache available)")
            continue

        iocs        = parse_feed(content, feed_name, feed_config)
        ioc_type    = feed_config["type"]
        threat_type = _THREAT_MAP.get(feed_name, "malicious")

        added = 0
        for ioc_value in iocs:
            try:
                cur.execute("""
                    INSERT OR IGNORE INTO iocs
                        (type, value, threat_type, source, first_added, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (ioc_type, ioc_value, threat_type, feed_name, now, now))
                if cur.rowcount > 0:
                    added += 1
            except Exception:
                pass

        # Update last_updated on already-known records from this feed
        cur.execute(
            "UPDATE iocs SET last_updated=? WHERE source=?",
            (now, feed_name)
        )

        cur.execute("""
            INSERT OR REPLACE INTO feed_status
                (feed_name, label, last_updated, ioc_count, status)
            VALUES (?, ?, ?, ?, 'OK')
        """, (feed_name, label, now, len(iocs)))

        conn.commit()
        total_new += added
        log.info("  %-30s %6d IOCs (%d new)", label, len(iocs), added)
        if callback:
            callback(f"  {label}: {len(iocs):,} IOCs ({added} new)")

    cur.execute("SELECT COUNT(*) FROM iocs")
    total = cur.fetchone()[0]
    conn.close()

    # Rebuild in-memory cache after update
    load_ioc_cache()

    summary = (
        f"Feed update complete. "
        f"Total IOCs in database: {total:,} ({total_new} newly added)"
    )
    log.info(summary)
    if callback:
        callback(summary)
    return total
