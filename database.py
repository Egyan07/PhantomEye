# =============================================================================
#   database.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Database initialisation.
# =============================================================================

import sqlite3

from config import DB_PATH
from logger import log


def init_database():
    """Create all tables if they do not already exist."""
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # IOC storage — all malicious IPs and domains
    cur.execute("""
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

    # Feed status — track when each feed was last downloaded
    cur.execute("""
        CREATE TABLE IF NOT EXISTS feed_status (
            feed_name    TEXT PRIMARY KEY,
            label        TEXT,
            last_updated TEXT,
            ioc_count    INTEGER,
            status       TEXT
        )
    """)

    # Alert history — every threat hit ever raised
    cur.execute("""
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
    log.info("Database ready: %s", DB_PATH)
