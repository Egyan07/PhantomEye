# =============================================================================
#   alerts.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Central alert dispatcher.
#
#   FIXES v1.2:
#   - SMTP now uses ssl.create_default_context() so the server certificate
#     is verified — prevents credential interception on hostile networks.
#   - Bare except: pass replaced with explicit logging so failures are visible.
#   - _is_duplicate and record_alert now share a single cursor to avoid
#     any TOCTOU window on the deduplication query.
# =============================================================================

import os
import ssl
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

    Returns True if the alert was recorded, False if suppressed by deduplication.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    _own_conn = conn is None
    if _own_conn:
        conn = sqlite3.connect(DB_PATH)

    try:
        # Deduplication and insert share the same connection/transaction
        if _is_duplicate(ioc_value, conn):
            log.debug("Alert suppressed (dedupe): %s", ioc_value)
            return False

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
        log.error("Failed to save alert for %s: %s", ioc_value, e)
        return False
    finally:
        if _own_conn:
            conn.close()

    # --- msg.exe desktop popup to admin PC ---
    try:
        short = f"PhantomEye [{severity}]: {alert_type} — {ioc_value}"
        subprocess.run(["msg", ADMIN_PC, short], capture_output=True, timeout=5)
    except Exception as e:
        log.debug("msg.exe notification failed (non-critical): %s", e)

    # --- Email ---
    if EMAIL_ENABLED:
        try:
            _send_email(severity, alert_type, ioc_value, context, details, now)
        except Exception as e:
            log.error("Email alert failed for %s: %s", ioc_value, e)

    return True


# ---------------------------------------------------------------------------
#   Private helpers
# ---------------------------------------------------------------------------

def _is_duplicate(ioc_value: str, conn: sqlite3.Connection) -> bool:
    """
    Return True if an alert for this IOC was already recorded within
    ALERT_DEDUPE_HOURS hours.  Uses the caller's connection so the check
    is in the same transaction as the subsequent INSERT.
    """
    cutoff = (
        datetime.now() - timedelta(hours=ALERT_DEDUPE_HOURS)
    ).strftime("%Y-%m-%d %H:%M:%S")
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE ioc_value = ? AND timestamp >= ?
        """, (ioc_value, cutoff))
        return cur.fetchone()[0] > 0
    except Exception as e:
        log.warning("Deduplication check failed for %s: %s", ioc_value, e)
        return False


def _get_email_password() -> str:
    """Read the email password from PHANTOMEYE_EMAIL_PASSWORD env var."""
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

    # FIX: use a proper SSL context so the server certificate is verified
    ctx = ssl.create_default_context()
    with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as s:
        s.ehlo()
        s.starttls(context=ctx)
        s.login(EMAIL_FROM, password)
        s.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
    log.info("Email alert sent for: %s", ioc_value)
