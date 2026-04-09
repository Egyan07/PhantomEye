# =============================================================================
#   reports.py — PhantomEye v1.3
#   Red Parrot Accounting Ltd
#
#   Self-contained dark-themed HTML report generator for alert history.
#   No third-party dependencies — stdlib only.
# =============================================================================

import sqlite3
from datetime import datetime

from config import DB_PATH
from logger import log


def generate_alert_report(output_path: str) -> int:
    """Generate HTML report from alert history. Returns alert count."""
    alerts = _fetch_alerts()
    html = _build_html(alerts)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    log.info("HTML report written: %s (%d alerts)", output_path, len(alerts))
    return len(alerts)


def _fetch_alerts() -> list[tuple]:
    """Fetch all alerts from DB, newest first."""
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT timestamp, severity, alert_type, ioc_value, ioc_type, "
                "source_feed, context, details FROM alerts ORDER BY id DESC"
            )
            return cur.fetchall()
        finally:
            conn.close()
    except Exception as e:
        log.error("Could not fetch alerts for report: %s", e)
        return []


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _build_html(alerts: list[tuple]) -> str:
    """Build self-contained dark-themed HTML report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for a in alerts:
        timestamp, severity, alert_type, ioc_value, ioc_type, source_feed, context, details = a
        sev_class = "critical" if severity == "CRITICAL" else "high"
        rows.append(
            f"<tr class='{sev_class}'>"
            f"<td>{_esc(timestamp)}</td>"
            f"<td>{_esc(severity)}</td>"
            f"<td>{_esc(alert_type)}</td>"
            f"<td><strong>{_esc(ioc_value)}</strong></td>"
            f"<td>{_esc(ioc_type)}</td>"
            f"<td>{_esc(source_feed)}</td>"
            f"<td>{_esc(context)}</td>"
            f"</tr>"
        )
    table_rows = "\n".join(rows) if rows else "<tr><td colspan='7'>No alerts recorded.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomEye Alert Report</title>
<style>
  body {{ background: #0d1117; color: #e6edf3; font-family: Consolas, monospace; margin: 0; padding: 20px; }}
  h1 {{ color: #2ea043; margin-bottom: 4px; }}
  .meta {{ color: #8b949e; margin-bottom: 20px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th {{ background: #1f6feb; color: white; padding: 10px 8px; text-align: left; }}
  td {{ padding: 8px; border-bottom: 1px solid #30363d; }}
  tr.critical td {{ color: #f85149; }}
  tr.high td {{ color: #d29922; }}
  .footer {{ margin-top: 30px; color: #30363d; font-size: 12px; }}
</style>
</head>
<body>
<h1>PhantomEye — Alert Report</h1>
<p class="meta">Generated: {_esc(now)} | Total alerts: {len(alerts)}</p>
<table>
<thead>
<tr><th>Time</th><th>Severity</th><th>Alert Type</th><th>IOC</th><th>Type</th><th>Source</th><th>Context</th></tr>
</thead>
<tbody>
{table_rows}
</tbody>
</table>
<p class="footer">Red Parrot Accounting Ltd — PhantomEye</p>
</body>
</html>"""
