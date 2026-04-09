# =============================================================================
#   feeds.py — PhantomEye v1.2.1
#   Red Parrot Accounting Ltd
#
#   Threat feed download, parsing, and IOC database ingestion.
#   Also manages the in-memory IOC set and metadata cache.
#
#   FIXES v1.2:
#   - Removed redundant double-whitelist check in parse_feed (was called
#     twice for url_extract and plain_domain formats).
#   - parse_feed now builds a set directly instead of list→set conversion.
#   - _meta_cache added so lookup.py never needs a DB round-trip for
#     total_iocs / last_updated — those values are populated once here
#     at cache-load time and refreshed after every feed update.
#   - Bare except: pass replaced with logged warnings throughout.
#
#   FIXES v1.2.1:
#   - load_ioc_cache: conn.close() moved to finally — was skipped on any
#     query exception, leaking the SQLite file handle.
#   - update_feeds: entire connection block now wrapped in try/finally —
#     conn.close() at the end of the function was unreachable on exception.
#   - check_stale_feeds: conn.close() moved to finally — same pattern as
#     load_ioc_cache.
# =============================================================================

import os
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime

from config import DB_PATH, FEEDS_DIR, THREAT_FEEDS
from custom_feeds import load_custom_feeds
from logger import log
from utils import (
    extract_domain_from_url,
    is_private_ip,
    is_valid_domain,
    is_valid_ip,
    is_whitelisted,
)

# ---------------------------------------------------------------------------
#   In-memory IOC sets — loaded once at startup, refreshed after feed update
# ---------------------------------------------------------------------------
_ioc_cache: dict[str, set] = {"ip": set(), "domain": set()}
_meta_cache: dict = {"total_iocs": 0, "last_updated": "Never"}


def load_ioc_cache() -> dict[str, set]:
    """
    Load all IOCs from the database into memory.
    Also populates _meta_cache so lookups never need extra DB round-trips.
    Call this once at startup and after every feed update.
    """
    global _ioc_cache
    _ioc_cache = {"ip": set(), "domain": set()}
    try:
        conn = sqlite3.connect(DB_PATH)
        # FIX: conn.close() moved into a finally block so it is always called
        # even when a query raises.  Previously it sat inside the try body and
        # was skipped on any exception, leaking the file handle.
        try:
            cur = conn.cursor()

            cur.execute("SELECT type, value FROM iocs")
            for ioc_type, value in cur.fetchall():
                if ioc_type in _ioc_cache:
                    _ioc_cache[ioc_type].add(value.lower())

            cur.execute("SELECT MAX(last_updated) FROM feed_status WHERE status='OK'")
            row = cur.fetchone()
            _meta_cache["last_updated"] = row[0] if row and row[0] else "Never"
            _meta_cache["total_iocs"] = len(_ioc_cache["ip"]) + len(_ioc_cache["domain"])
        finally:
            conn.close()
        log.info("IOC cache loaded: %d IPs, %d domains", len(_ioc_cache["ip"]), len(_ioc_cache["domain"]))
    except Exception as e:
        log.warning("Could not load IOC cache: %s", e)
    return _ioc_cache


def get_ioc_cache() -> dict[str, set]:
    """Return the current in-memory IOC cache (may be empty if not yet loaded)."""
    return _ioc_cache


def get_meta_cache() -> dict:
    """Return cached metadata: total_iocs, last_updated."""
    return _meta_cache


def feeds_loaded() -> int:
    """Return total IOC count from the meta cache (no DB I/O)."""
    return _meta_cache["total_iocs"]


def get_last_feed_time() -> str:
    """Return last successful feed update time from the meta cache (no DB I/O)."""
    return _meta_cache["last_updated"]


# ---------------------------------------------------------------------------
#   Download
# ---------------------------------------------------------------------------


def download_feed(feed_name: str, feed_config: dict) -> str | None:
    """
    Download a single threat feed and return raw content as a string.
    Falls back to the cached file on download failure.
    """
    url = feed_config["url"]
    filepath = os.path.join(FEEDS_DIR, f"{feed_name}.txt")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PhantomEye/2.0.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return content
    except urllib.error.URLError as e:
        log.warning("Feed download failed [%s]: %s", feed_name, e)
        if os.path.exists(filepath):
            log.info("Using cached feed for: %s", feed_name)
            try:
                with open(filepath, encoding="utf-8") as f:
                    return f.read()
            except OSError as read_err:
                log.error("Could not read cached feed [%s]: %s", feed_name, read_err)
        return None


# ---------------------------------------------------------------------------
#   Parsing
# ---------------------------------------------------------------------------

_THREAT_MAP = {
    "feodo_ips": "c2",
    "emerging_threats": "compromised",
    "cins_score": "bad_actor",
    "abuse_ssl": "malware",
    "urlhaus_domains": "malware",
    "openphish": "phishing",
    "botvrij_domains": "malware",
    "botvrij_ips": "malware",
}


def parse_feed(content: str, feed_name: str, feed_config: dict) -> list[str]:
    """
    Parse feed content into a deduplicated list of IOC values.

    Supported formats: plain_ip, feodo_csv, abuse_ssl_csv,
                       url_extract, plain_domain.

    FIX: Builds a set directly (no list→set round-trip).
    FIX: Single whitelist check at the end — removed redundant inline checks.
    """
    iocs: set[str] = set()
    fmt = feed_config["format"]
    ioc_type = feed_config["type"]
    lines = content.splitlines()

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
            if domain and is_valid_domain(domain):
                value = domain

        elif fmt == "plain_domain":
            candidate = line.split()[0].lower().strip(".")
            if is_valid_domain(candidate):
                value = candidate

        # Single whitelist check for all formats
        if value and not is_whitelisted(value, ioc_type):
            iocs.add(value.lower())

    return list(iocs)


def _detect_ip_column(lines: list[str], fmt: str) -> int:
    """
    Find the column index that contains the IP in a CSV feed by inspecting
    the header row. Falls back to hardcoded defaults if no header is found.
    """
    defaults = {"feodo_csv": 1, "abuse_ssl_csv": 1}
    for line in lines[:5]:
        line = line.strip()
        if not line or not line.startswith("#"):
            continue
        header = line.lstrip("# ").lower()
        cols = [c.strip() for c in header.split(",")]
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
    Reloads the in-memory IOC cache and meta cache when done.

    callback: optional callable(str) for GUI progress messages.
    Returns total IOC count in database after update.
    """
    log.info("=" * 60)
    log.info("PhantomEye v1.2 — Updating threat feeds")
    log.info("=" * 60)

    # FIX: wrap the entire connection lifetime in try/finally so the handle is
    # always closed — even if an unexpected exception escapes the feed loop.
    # Previously conn.close() at the bottom was unreachable on any exception,
    # leaving the SQLite file handle open until the GC ran.
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_new = 0
    total = 0

    all_feeds = {**THREAT_FEEDS, **load_custom_feeds()}

    try:
        for feed_name, feed_config in all_feeds.items():
            label = feed_config["label"]
            if callback:
                callback(f"Downloading: {label}...")
            log.info("Downloading: %s", label)

            content = download_feed(feed_name, feed_config)
            if content is None:
                cur.execute(
                    """
                    INSERT OR REPLACE INTO feed_status
                        (feed_name, label, last_updated, ioc_count, status)
                    VALUES (?, ?, ?, 0, 'FAILED')
                """,
                    (feed_name, label, now),
                )
                conn.commit()
                msg = f"  {label}: FAILED (no cache available)"
                log.warning(msg)
                if callback:
                    callback(msg)
                continue

            iocs = parse_feed(content, feed_name, feed_config)
            ioc_type = feed_config["type"]
            threat_type = _THREAT_MAP.get(feed_name, "malicious")

            added = 0
            for ioc_value in iocs:
                try:
                    cur.execute(
                        """
                        INSERT OR IGNORE INTO iocs
                            (type, value, threat_type, source, first_added, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """,
                        (ioc_type, ioc_value, threat_type, feed_name, now, now),
                    )
                    if cur.rowcount > 0:
                        added += 1
                except Exception as e:
                    log.debug("IOC insert failed [%s / %s]: %s", feed_name, ioc_value, e)

            cur.execute("UPDATE iocs SET last_updated=? WHERE source=?", (now, feed_name))
            cur.execute(
                """
                INSERT OR REPLACE INTO feed_status
                    (feed_name, label, last_updated, ioc_count, status)
                VALUES (?, ?, ?, ?, 'OK')
            """,
                (feed_name, label, now, len(iocs)),
            )

            conn.commit()
            total_new += added
            log.info("  %-30s %6d IOCs (%d new)", label, len(iocs), added)
            if callback:
                callback(f"  {label}: {len(iocs):,} IOCs ({added} new)")

        cur.execute("SELECT COUNT(*) FROM iocs")
        total = cur.fetchone()[0]
    finally:
        conn.close()

    # Rebuild both caches after update
    load_ioc_cache()

    summary = f"Feed update complete. Total IOCs in database: {total:,} ({total_new} newly added)"
    log.info(summary)
    if callback:
        callback(summary)
    return total


def check_stale_feeds() -> list[str]:
    """
    Return a list of feed names that have FAILED status or have never run.
    Used by --check CLI mode and the dashboard health indicator.
    """
    stale = []
    all_feeds = {**THREAT_FEEDS, **load_custom_feeds()}
    try:
        conn = sqlite3.connect(DB_PATH)
        # FIX: conn.close() moved into a finally block so it is always called
        # even when a SELECT raises.  Previously it sat at the bottom of the
        # try body and was skipped on any exception, leaking the file handle.
        try:
            cur = conn.cursor()
            for feed_name in all_feeds:
                cur.execute("SELECT status FROM feed_status WHERE feed_name=?", (feed_name,))
                row = cur.fetchone()
                if row is None or row[0] != "OK":
                    stale.append(feed_name)
        finally:
            conn.close()
    except Exception as e:
        log.warning("Could not check feed health: %s", e)
    return stale
