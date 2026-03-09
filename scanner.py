# =============================================================================
#   scanner.py — PhantomEye v1.1
#   Red Parrot Accounting Ltd
#
#   Three scan engines:
#     scan_firewall_logs()    — Windows Firewall pfirewall.log
#     scan_dns_cache()        — Windows DNS resolver cache via PowerShell
#     analyse_email_headers() — Raw email header IOC extraction
#
#   BUG FIXES:
#   - Firewall scanner now alerts on both ALLOW *and* DROP entries.
#     A blocked connection to a C2 server is reported as CRITICAL (infection
#     indicator); an allowed connection is reported as CRITICAL (active C2).
#   - All scan loops share one SQLite connection passed into record_alert()
#     instead of opening a new connection per alert.
#   - Variable shadowing in scan_dns_cache fixed (subprocess result
#     renamed to proc_result).
#   - IPv6 addresses are validated and checked (was silently skipped).
# =============================================================================

import re
import sqlite3
import subprocess
from datetime import datetime, timedelta

from config import DB_PATH, FIREWALL_LOG, FIREWALL_LOG_DAYS
from logger import log
from utils import is_valid_ip, is_valid_ipv4, is_private_ip, is_valid_domain, is_whitelisted
from lookup import is_ioc_known
from alerts import record_alert


# ---------------------------------------------------------------------------
#   Firewall log scanner
# ---------------------------------------------------------------------------

def scan_firewall_logs(callback=None) -> list[dict]:
    """
    Parse Windows Firewall log and check all destination IPs (both ALLOW
    and DROP entries) against the threat intelligence database.

    BUG FIX: v1.0 only checked ALLOW entries. A DROP to a C2 server is
    arguably more important — it means a machine is infected and actively
    trying to phone home, but was caught by the firewall.

    Returns list of hit dicts.
    """
    import os
    log.info("Scanning Windows Firewall logs...")

    if not os.path.exists(FIREWALL_LOG):
        msg = (
            f"Firewall log not found: {FIREWALL_LOG}\n"
            f"Enable logging: Windows Defender Firewall → Advanced Settings "
            f"→ Properties → each Profile → Logging"
        )
        log.warning(msg)
        if callback:
            callback("WARNING: " + msg)
        return []

    hits    = []
    cutoff  = datetime.now() - timedelta(days=FIREWALL_LOG_DAYS)
    checked = set()   # Avoid re-checking the same IP twice per run

    conn = sqlite3.connect(DB_PATH)
    try:
        with open(FIREWALL_LOG, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                # Format: date time action protocol src-ip dst-ip src-port dst-port ...
                parts = line.split()
                if len(parts) < 6:
                    continue

                try:
                    log_time = datetime.strptime(
                        f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S"
                    )
                    if log_time < cutoff:
                        continue
                except ValueError:
                    continue

                action = parts[2].upper() if len(parts) > 2 else ""
                dst_ip = parts[5]          if len(parts) > 5 else ""

                # BUG FIX: check both ALLOW and DROP
                if action not in ("ALLOW", "DROP"):
                    continue
                if not is_valid_ip(dst_ip):
                    continue
                if is_private_ip(dst_ip):
                    continue
                if dst_ip in checked:
                    continue

                checked.add(dst_ip)

                if not is_ioc_known(dst_ip, "ip"):
                    continue

                # Differentiate: DROP = infection attempt caught; ALLOW = active connection
                if action == "DROP":
                    sev     = "CRITICAL"
                    a_type  = "MALICIOUS IP — BLOCKED BY FIREWALL (infection indicator)"
                    detail  = (
                        "A machine on this network attempted to connect to a known malicious IP "
                        "and was blocked by the firewall. This strongly indicates an infected machine."
                    )
                else:
                    sev     = "CRITICAL"
                    a_type  = "MALICIOUS IP IN FIREWALL LOG — ACTIVE CONNECTION"
                    detail  = (
                        "An outbound connection to a known malicious IP was allowed through "
                        "the firewall. Investigate immediately."
                    )

                context = f"Firewall log — action={action} at {parts[0]} {parts[1]}"
                recorded = record_alert(
                    severity=sev, alert_type=a_type,
                    ioc_value=dst_ip, ioc_type="ip",
                    source_feed="firewall_scan", context=context,
                    details=detail, conn=conn,
                )
                conn.commit()

                hit = {
                    "ioc":     dst_ip,
                    "type":    "ip",
                    "action":  action,
                    "context": context,
                }
                hits.append(hit)
                msg = f"[HIT] {dst_ip} — {action} — {'(new alert)' if recorded else '(dedupe)'}"
                log.warning(msg)
                if callback:
                    callback(msg)

    except PermissionError:
        log.error("Cannot read firewall log — run as Administrator")
        if callback:
            callback("ERROR: Cannot read firewall log — run as Administrator")
    finally:
        conn.close()

    log.info(
        "Firewall scan complete. %d unique IPs checked, %d malicious hits.",
        len(checked), len(hits)
    )
    if callback:
        callback(
            f"Firewall scan: {len(checked)} IPs checked, {len(hits)} malicious hits"
        )
    return hits


# ---------------------------------------------------------------------------
#   DNS cache scanner
# ---------------------------------------------------------------------------

def scan_dns_cache(callback=None) -> list[dict]:
    """
    Read the Windows DNS resolver cache via PowerShell and check all domains
    against the threat intelligence database.

    BUG FIX: variable shadowing — subprocess result renamed proc_result
    so it can't be confused with the IOC lookup result dict.
    """
    log.info("Scanning DNS cache...")
    hits = []

    try:
        ps_cmd = (
            "Get-DnsClientCache | "
            "Select-Object -ExpandProperty Entry | "
            "Sort-Object -Unique"
        )
        proc_result = subprocess.run(      # was: result = subprocess.run(...)
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        domains = [
            d.strip().lower()
            for d in proc_result.stdout.splitlines()
            if d.strip()
        ]
    except Exception as e:
        log.error("Could not read DNS cache: %s", e)
        if callback:
            callback(f"ERROR reading DNS cache: {e}")
        return []

    checked = set()
    conn    = sqlite3.connect(DB_PATH)
    try:
        for domain in domains:
            if not is_valid_domain(domain) or domain in checked:
                continue
            if is_whitelisted(domain, "domain"):
                continue

            checked.add(domain)

            if not is_ioc_known(domain, "domain"):
                continue

            context  = "Found in Windows DNS resolver cache"
            recorded = record_alert(
                severity="CRITICAL",
                alert_type="MALICIOUS DOMAIN IN DNS CACHE",
                ioc_value=domain, ioc_type="domain",
                source_feed="dns_scan", context=context,
                details="Machine recently resolved this known malicious domain.",
                conn=conn,
            )
            conn.commit()

            hit = {"ioc": domain, "type": "domain", "context": context}
            hits.append(hit)
            msg = f"[HIT] {domain} — {'(new alert)' if recorded else '(dedupe)'}"
            log.warning(msg)
            if callback:
                callback(msg)
    finally:
        conn.close()

    log.info(
        "DNS scan complete. %d domains checked, %d hits.",
        len(checked), len(hits)
    )
    if callback:
        callback(f"DNS scan: {len(checked)} domains checked, {len(hits)} malicious hits")
    return hits


# ---------------------------------------------------------------------------
#   Email header analyser
# ---------------------------------------------------------------------------

def analyse_email_headers(header_text: str, callback=None) -> str:
    """
    Parse raw email headers, extract all sender/relay IPs and domains,
    check each against the threat intelligence feeds.

    Works with headers pasted from Outlook (File → Properties → Internet Headers)
    or Gmail (Show Original).

    Returns a formatted multi-line report string.
    """
    lines          = header_text.splitlines()
    ip_pattern     = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    domain_pattern = re.compile(
        r"from\s+([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", re.IGNORECASE
    )

    # --- Extract From and Reply-To domains ---
    from_domain = ""
    reply_domain = ""
    for line in lines:
        ll = line.lower()
        if ll.startswith("from:") and not from_domain:
            m = re.search(r"@([a-zA-Z0-9.\-]+)", line)
            if m:
                from_domain = m.group(1).lower()
        if ll.startswith("reply-to:") and not reply_domain:
            m = re.search(r"@([a-zA-Z0-9.\-]+)", line)
            if m:
                reply_domain = m.group(1).lower()

    mismatch_alert = bool(from_domain and reply_domain and from_domain != reply_domain)

    # --- Extract IPs from Received headers ---
    received_ips = []
    for line in lines:
        if line.lower().startswith("received:") or "[" in line:
            for ip in ip_pattern.findall(line):
                if is_valid_ip(ip) and not is_private_ip(ip):
                    received_ips.append(ip)

    # --- Extract domains from Received headers ---
    received_domains = []
    for line in lines:
        if line.lower().startswith("received:"):
            for domain in domain_pattern.findall(line):
                domain = domain.lower().strip(".")
                if is_valid_domain(domain) and not is_whitelisted(domain, "domain"):
                    received_domains.append(domain)

    # --- Build report ---
    report = []
    report.append("=" * 60)
    report.append("  PhantomEye — Email Header Analysis")
    report.append("=" * 60)

    if from_domain:
        report.append(f"  From domain   : {from_domain}")
    if reply_domain:
        report.append(f"  Reply-To      : {reply_domain}")
    if mismatch_alert:
        report.append("  ⚠ WARNING: From ≠ Reply-To — possible phishing redirect!")

    unique_ips     = list(dict.fromkeys(received_ips))     # dedup, preserve order
    unique_domains = list(dict.fromkeys(received_domains))[:20]

    report.append(f"  IPs found     : {len(unique_ips)}")
    report.append(f"  Domains found : {len(unique_domains)}")
    report.append("-" * 60)

    threat_count = 0
    conn = sqlite3.connect(DB_PATH)
    try:
        for ip in unique_ips:
            hit = is_ioc_known(ip, "ip")
            if hit:
                threat_count += 1
                record_alert(
                    "CRITICAL", "MALICIOUS IP IN EMAIL HEADER",
                    ip, "ip", "email_analysis", "Email header analysis", "",
                    conn=conn,
                )
                conn.commit()
                report.append(f"  IP  {ip:<20} ⛔ MALICIOUS")
            else:
                report.append(f"  IP  {ip:<20} ✓ Clean")

        for domain in unique_domains:
            if is_whitelisted(domain, "domain"):
                continue
            hit = is_ioc_known(domain, "domain")
            if hit:
                threat_count += 1
                record_alert(
                    "CRITICAL", "MALICIOUS DOMAIN IN EMAIL HEADER",
                    domain, "domain", "email_analysis", "Email header analysis", "",
                    conn=conn,
                )
                conn.commit()
                report.append(f"  DOM {domain:<35} ⛔ MALICIOUS")
            else:
                report.append(f"  DOM {domain:<35} ✓ Clean")
    finally:
        conn.close()

    report.append("-" * 60)
    if threat_count > 0 or mismatch_alert:
        report.append(f"  VERDICT: ⛔ SUSPICIOUS — {threat_count} threat(s) detected")
        report.append("  Do NOT click links or open attachments in this email.")
    else:
        report.append("  VERDICT: ✓ No known threats found in email headers.")
        report.append("  Note: Clean headers don't guarantee the email is safe.")
    report.append("=" * 60)

    return "\n".join(report)
