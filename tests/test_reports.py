# =============================================================================
#   tests/test_reports.py — PhantomEye v1.3
#   Red Parrot Accounting Ltd
#
#   Unit tests for reports.py — HTML report generation.
#   Uses tmp_path fixtures so no persistent files are written.
#   Run with: pytest tests/test_reports.py -v
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import sqlite3
from unittest.mock import patch

import pytest


def _make_tmp_db(tmp_path):
    """Create a temporary SQLite DB with the alerts schema and return its path."""
    db_path = str(tmp_path / "test.db")
    conn = sqlite3.connect(db_path)
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
    return db_path, conn


def _insert_alert(conn, **overrides):
    """Insert a single alert row with sensible defaults."""
    defaults = {
        "timestamp": "2026-04-09 12:00:00",
        "severity": "CRITICAL",
        "alert_type": "Threat Feed Match",
        "ioc_value": "1.2.3.4",
        "ioc_type": "ip",
        "source_feed": "feodo_ips",
        "context": "Firewall log",
        "details": "matched line 42",
    }
    defaults.update(overrides)
    conn.execute(
        "INSERT INTO alerts (timestamp, severity, alert_type, ioc_value, "
        "ioc_type, source_feed, context, details) VALUES (?,?,?,?,?,?,?,?)",
        (
            defaults["timestamp"],
            defaults["severity"],
            defaults["alert_type"],
            defaults["ioc_value"],
            defaults["ioc_type"],
            defaults["source_feed"],
            defaults["context"],
            defaults["details"],
        ),
    )
    conn.commit()


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    with (
        patch("config.LOG_DIR", str(tmp_path / "logs")),
        patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
        patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
        patch("config.DB_PATH", str(tmp_path / "test.db")),
        patch("config.ADMIN_PC", "TESTPC"),
        patch("config.EMAIL_ENABLED", False),
        patch("config.WHITELIST_IPS", []),
        patch("config.WHITELIST_DOMAINS", []),
    ):
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield


from reports import _build_html, _esc

# ---- TestHTMLEscape --------------------------------------------------------


class TestHTMLEscape:
    def test_escapes_angle_brackets(self):
        assert _esc("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"

    def test_escapes_ampersand(self):
        assert _esc("foo & bar") == "foo &amp; bar"

    def test_escapes_quotes(self):
        assert _esc('attr="val"') == "attr=&quot;val&quot;"

    def test_plain_text_unchanged(self):
        assert _esc("hello world 123") == "hello world 123"


# ---- TestBuildHTML ---------------------------------------------------------


class TestBuildHTML:
    def test_empty_alerts(self):
        html = _build_html([])
        assert "No alerts recorded." in html
        assert "Total alerts: 0" in html

    def test_contains_alert_data(self):
        alerts = [
            ("2026-04-09 12:00:00", "CRITICAL", "Feed Match", "1.2.3.4", "ip", "feodo", "Firewall", "details"),
        ]
        html = _build_html(alerts)
        assert "1.2.3.4" in html
        assert "Feed Match" in html
        assert "Total alerts: 1" in html

    def test_high_severity_class(self):
        alerts = [
            ("2026-04-09 12:00:00", "HIGH", "Feed Match", "evil.com", "domain", "urlhaus", "DNS", "details"),
        ]
        html = _build_html(alerts)
        assert "class='high'" in html

    def test_html_injection_escaped(self):
        alerts = [
            (
                "2026-04-09 12:00:00",
                "CRITICAL",
                "<script>alert(1)</script>",
                "<img src=x>",
                "ip",
                "test",
                "ctx",
                "d",
            ),
        ]
        html = _build_html(alerts)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "&lt;img src=x&gt;" in html

    def test_valid_html_structure(self):
        html = _build_html([])
        assert html.startswith("<!DOCTYPE html>")
        assert "<html lang=" in html
        assert "</html>" in html
        assert "<table>" in html
        assert "</table>" in html


# ---- TestGenerateAlertReport -----------------------------------------------


class TestGenerateAlertReport:
    def test_generates_file(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, severity TEXT, alert_type TEXT,
                ioc_value TEXT, ioc_type TEXT, source_feed TEXT,
                context TEXT, details TEXT
            )
        """)
        conn.commit()
        conn.close()

        out = str(tmp_path / "report.html")
        with patch("reports.DB_PATH", db_path):
            from reports import generate_alert_report

            count = generate_alert_report(out)
        assert os.path.exists(out)
        assert count == 0

    def test_includes_alerts(self, tmp_path):
        db_path, conn = _make_tmp_db(tmp_path)
        _insert_alert(conn, ioc_value="10.20.30.40", severity="CRITICAL")
        _insert_alert(conn, ioc_value="evil.example.com", severity="HIGH")
        conn.close()

        out = str(tmp_path / "report.html")
        with patch("reports.DB_PATH", db_path):
            from reports import generate_alert_report

            count = generate_alert_report(out)
        assert count == 2
        with open(out, encoding="utf-8") as f:
            html = f.read()
        assert "10.20.30.40" in html
        assert "evil.example.com" in html
