# =============================================================================
#   tests/test_alerts.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Unit tests for alerts.py — deduplication logic and record_alert behaviour.
#   Uses in-memory SQLite so no files are written.
#   Run with: pytest tests/test_alerts.py -v
# =============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import sqlite3
import pytest
from unittest.mock import patch
from datetime import datetime, timedelta


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    with patch("config.LOG_DIR",             str(tmp_path / "logs")), \
         patch("config.FEEDS_DIR",           str(tmp_path / "feeds")), \
         patch("config.LOG_FILE",            str(tmp_path / "phantom_eye.log")), \
         patch("config.DB_PATH",             ":memory:"), \
         patch("config.ADMIN_PC",            "TESTPC"), \
         patch("config.ALERT_DEDUPE_HOURS",  24), \
         patch("config.EMAIL_ENABLED",       False), \
         patch("config.WHITELIST_IPS",       []), \
         patch("config.WHITELIST_DOMAINS",   []):
        os.makedirs(str(tmp_path / "logs"),  exist_ok=True)
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield


def _make_alerts_table():
    """Return an in-memory SQLite connection with the alerts schema."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE alerts (
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
    return conn


from alerts import _is_duplicate, record_alert


class TestIsDuplicate:
    def test_no_prior_alerts_returns_false(self):
        conn = _make_alerts_table()
        assert not _is_duplicate("1.2.3.4", conn)

    def test_recent_alert_returns_true(self):
        conn = _make_alerts_table()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO alerts (timestamp, severity, alert_type, ioc_value, "
            "ioc_type, source_feed, context, details) VALUES (?,?,?,?,?,?,?,?)",
            (now, "CRITICAL", "TEST", "1.2.3.4", "ip", "test", "", "")
        )
        conn.commit()
        assert _is_duplicate("1.2.3.4", conn)

    def test_old_alert_returns_false(self):
        conn = _make_alerts_table()
        old_time = (datetime.now() - timedelta(hours=25)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO alerts (timestamp, severity, alert_type, ioc_value, "
            "ioc_type, source_feed, context, details) VALUES (?,?,?,?,?,?,?,?)",
            (old_time, "CRITICAL", "TEST", "1.2.3.4", "ip", "test", "", "")
        )
        conn.commit()
        assert not _is_duplicate("1.2.3.4", conn)

    def test_different_ioc_not_duplicate(self):
        conn = _make_alerts_table()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO alerts (timestamp, severity, alert_type, ioc_value, "
            "ioc_type, source_feed, context, details) VALUES (?,?,?,?,?,?,?,?)",
            (now, "CRITICAL", "TEST", "9.9.9.9", "ip", "test", "", "")
        )
        conn.commit()
        assert not _is_duplicate("1.2.3.4", conn)


class TestRecordAlert:
    def test_records_new_alert(self):
        conn = _make_alerts_table()
        with patch("subprocess.run"), \
             patch("alerts.DB_PATH", ":memory:"):
            result = record_alert(
                "CRITICAL", "TEST ALERT", "1.2.3.4", "ip",
                "test_feed", "test context", "test details",
                conn=conn,
            )
        assert result is True
        cur = conn.execute("SELECT COUNT(*) FROM alerts WHERE ioc_value='1.2.3.4'")
        assert cur.fetchone()[0] == 1

    def test_deduplication_suppresses_second_alert(self):
        conn = _make_alerts_table()
        with patch("subprocess.run"), \
             patch("alerts.DB_PATH", ":memory:"):
            record_alert(
                "CRITICAL", "TEST ALERT", "1.2.3.4", "ip",
                "test_feed", "", "", conn=conn,
            )
            conn.commit()
            result = record_alert(
                "CRITICAL", "TEST ALERT", "1.2.3.4", "ip",
                "test_feed", "", "", conn=conn,
            )
        assert result is False
        cur = conn.execute("SELECT COUNT(*) FROM alerts WHERE ioc_value='1.2.3.4'")
        assert cur.fetchone()[0] == 1

    def test_msg_failure_does_not_raise(self):
        conn = _make_alerts_table()
        with patch("subprocess.run", side_effect=FileNotFoundError("msg not found")), \
             patch("alerts.DB_PATH", ":memory:"):
            # Should not raise even if msg.exe is missing
            result = record_alert(
                "CRITICAL", "TEST", "5.5.5.5", "ip",
                "test", "", "", conn=conn,
            )
        assert result is True
