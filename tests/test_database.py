# =============================================================================
#   tests/test_database.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Unit tests for database.py — table creation and idempotency.
#   Uses a temp file path so no files persist between tests.
# =============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import sqlite3
import pytest
from unittest.mock import patch


@pytest.fixture
def tmp_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    with patch("config.DB_PATH", db_path), \
         patch("config.LOG_DIR",   str(tmp_path / "logs")), \
         patch("config.FEEDS_DIR", str(tmp_path / "feeds")), \
         patch("config.LOG_FILE",  str(tmp_path / "phantom_eye.log")):
        os.makedirs(str(tmp_path / "logs"),  exist_ok=True)
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield db_path


from database import init_database


class TestInitDatabase:
    def test_creates_iocs_table(self, tmp_db):
        with patch("database.DB_PATH", tmp_db):
            init_database()
        conn = sqlite3.connect(tmp_db)
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='iocs'"
        )
        assert cur.fetchone() is not None
        conn.close()

    def test_creates_feed_status_table(self, tmp_db):
        with patch("database.DB_PATH", tmp_db):
            init_database()
        conn = sqlite3.connect(tmp_db)
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='feed_status'"
        )
        assert cur.fetchone() is not None
        conn.close()

    def test_creates_alerts_table(self, tmp_db):
        with patch("database.DB_PATH", tmp_db):
            init_database()
        conn = sqlite3.connect(tmp_db)
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
        )
        assert cur.fetchone() is not None
        conn.close()

    def test_idempotent_second_call(self, tmp_db):
        """Calling init_database() twice must not raise."""
        with patch("database.DB_PATH", tmp_db):
            init_database()
            init_database()  # Should not raise

    def test_iocs_unique_constraint(self, tmp_db):
        """iocs table must enforce UNIQUE(type, value)."""
        with patch("database.DB_PATH", tmp_db):
            init_database()
        conn = sqlite3.connect(tmp_db)
        now = "2024-01-01 00:00:00"
        conn.execute(
            "INSERT INTO iocs (type, value, threat_type, source, first_added, last_updated) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("ip", "1.2.3.4", "c2", "test", now, now)
        )
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO iocs (type, value, threat_type, source, first_added, last_updated) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("ip", "1.2.3.4", "c2", "test", now, now)
            )
        conn.close()

    def test_alerts_table_columns(self, tmp_db):
        """Verify all expected columns exist in alerts table."""
        with patch("database.DB_PATH", tmp_db):
            init_database()
        conn = sqlite3.connect(tmp_db)
        cur = conn.execute("PRAGMA table_info(alerts)")
        cols = {row[1] for row in cur.fetchall()}
        expected = {"id", "timestamp", "severity", "alert_type",
                    "ioc_value", "ioc_type", "source_feed", "context", "details"}
        assert expected.issubset(cols)
        conn.close()
