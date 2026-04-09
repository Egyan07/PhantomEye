# =============================================================================
#   database.py — PhantomEye v1.2.1
#   Red Parrot Accounting Ltd
#
#   Database initialisation.
#
#   FIX v1.2.1:
#   - init_database: connection now closed in a finally block — was leaked
#     on any exception between sqlite3.connect() and conn.close().
# =============================================================================

import sqlite3

from config import DB_PATH
from logger import log


def init_database() -> None:
    """Create all tables if they do not already exist."""
    # FIX: wrap in try/finally so the connection is always closed even if
    # a CREATE TABLE statement raises (e.g. DB path not writable).
    # Previously any exception between sqlite3.connect() and conn.close()
    # would leave the file handle open until the GC collected it.
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()

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
    finally:
        conn.close()
    log.info("Database ready: %s", DB_PATH)
