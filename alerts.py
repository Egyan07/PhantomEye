# =============================================================================
#   alerts.py — PhantomEye v1.1
#   Red Parrot Accounting Ltd
#
#   Central alert dispatcher.
#
#   BUG FIXES:
#   - Each call no longer opens its own DB connection; a single connection
#     is passed in from the scan loop (eliminates thousands of connect/close
#     cycles during a full firewall scan).
#   - Alert deduplication: an IOC that has already triggered an alert within
#     ALERT_DEDUPE_HOURS will not generate a duplicate alert, preventing
#     alert storms from beaconing malware.
#   - Email password read from PHANTOMEYE_EMAIL_PASSWORD env var — never
#     stored in source code.
# =============================================================================

import os
import sqlite3
import smtplib
import subprocess
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import (
    DB_PATH, ADMIN_PC, ALERT_DEDUPE_HOURS,
    EMAIL_ENABLED, EMAIL_FROM, EMAIL_TO,
    EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT,
)
from logger import log


def record_alert(
    severity:    str,
    alert_type:  str,
    ioc_value:   str,
    ioc_type:    str,
    source_feed: str,
    context:     str,
    details:     str,
    conn:        sqlite3.Connection = None,
) -> bool:
    """
    Dispatch an alert: save to DB, send msg.exe notification, optionally email.

    conn: optional open SQLite connection from the caller's scan loop.
          If None, a short-lived connection is opened and closed here.
          Passing the caller's connection avoids per-alert connect overhead.

    Returns True if the alert was recorded, False if suppressed by deduplication.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- Deduplication check ---
    if _is_duplicate(ioc_value, conn):
        log.debug("Alert suppressed (dedupe): %s", ioc_value)
        return False

    # --- Save to DB ---
    _own_conn = conn is None
    if _own_conn:
        conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("""
            INSERT INTO alerts
                (timestamp, severity, alert_type, ioc_value, ioc_type,
                 source_feed, context, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (now, severity, alert_type, ioc_value, ioc_type,
              source_feed, context, details))
        if _own_conn:
            conn.commit()
    except Exception as e:
        log.error("Failed to save alert: %s", e)
    finally:
        if _own_conn:
            conn.close()

    # --- msg.exe to admin PC ---
    try:
        short = f"PhantomEye [{severity}]: {alert_type} — {ioc_value}"
        subprocess.run(["msg", ADMIN_PC, short], capture_output=True, timeout=5)
    except Exception:
        pass

    # --- Email ---
    if EMAIL_ENABLED:
        try:
            _send_email(severity, alert_type, ioc_value, context, details, now)
        except Exception as e:
            log.error("Email alert failed: %s", e)

    return True


# ---------------------------------------------------------------------------
#   Private helpers
# ---------------------------------------------------------------------------

def _is_duplicate(ioc_value: str, conn: sqlite3.Connection | None) -> bool:
    """
    Return True if an alert for this IOC was already recorded within
    ALERT_DEDUPE_HOURS hours.
    """
    cutoff = (
        datetime.now() - timedelta(hours=ALERT_DEDUPE_HOURS)
    ).strftime("%Y-%m-%d %H:%M:%S")

    _own_conn = conn is None
    if _own_conn:
        conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE ioc_value = ? AND timestamp >= ?
        """, (ioc_value, cutoff))
        count = cur.fetchone()[0]
        return count > 0
    except Exception:
        return False
    finally:
        if _own_conn:
            conn.close()


def _get_email_password() -> str:
    """
    Read the email password from the PHANTOMEYE_EMAIL_PASSWORD env var.
    Never store credentials in source files.
    """
    pwd = os.environ.get("PHANTOMEYE_EMAIL_PASSWORD", "")
    if not pwd:
        log.warning(
            "EMAIL_ENABLED is True but PHANTOMEYE_EMAIL_PASSWORD env var "
            "is not set. Email alert skipped."
        )
    return pwd


def _send_email(
    severity:   str,
    alert_type: str,
    ioc_value:  str,
    context:    str,
    details:    str,
    timestamp:  str,
) -> None:
    password = _get_email_password()
    if not password:
        return

    body = (
        f"PhantomEye Alert\n"
        f"Red Parrot Accounting Ltd\n\n"
        f"Severity   : {severity}\n"
        f"Alert      : {alert_type}\n"
        f"IOC        : {ioc_value}\n"
        f"Context    : {context}\n"
        f"Details    : {details}\n"
        f"Time       : {timestamp}\n"
    )
    msg            = MIMEMultipart()
    msg["From"]    = EMAIL_FROM
    msg["To"]      = EMAIL_TO
    msg["Subject"] = f"[PhantomEye {severity}] {alert_type}: {ioc_value}"
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as s:
        s.ehlo()
        s.starttls()
        s.login(EMAIL_FROM, password)
        s.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
    log.info("Email alert sent for: %s", ioc_value)
