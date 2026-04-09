# =============================================================================
#   scanner.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Three scan engines:
#     scan_firewall_logs()    — Windows Firewall pfirewall.log
#     scan_dns_cache()        — Windows DNS resolver cache via PowerShell
#     analyse_email_headers() — Raw email header IOC extraction
#
#   FIXES v1.2:
#   - scan_firewall_logs now also checks src_ip (inbound from malicious IP).
#   - analyse_email_headers: IP extraction no longer triggered by any "[" in
#     a line — now restricted to Received: headers only, eliminating false
#     positives from Message-ID, Content-Type, etc.
#   - Bare except: pass replaced with logged warnings.
#   - Domain deduplication cap ([:20]) raised to 50 for better coverage.
# =============================================================================

import re
import sqlite3
import subprocess
from datetime import datetime, timedelta

from alerts import record_alert
from config import DB_PATH, FIREWALL_LOG, FIREWALL_LOG_DAYS
from logger import log
from lookup import is_ioc_known
from utils import is_private_ip, is_valid_domain, is_valid_ip, is_whitelisted

# ---------------------------------------------------------------------------
#   Firewall log scanner
# ---------------------------------------------------------------------------


def scan_firewall_logs(callback=None) -> list[dict]:
    """
    Parse Windows Firewall log and check destination AND source IPs against
    the threat intelligence database.

    - ALLOW + malicious dst_ip → active outbound C2 connection (CRITICAL)
    - DROP  + malicious dst_ip → infection attempt caught by firewall (CRITICAL)
    - ALLOW/DROP + malicious src_ip → inbound scan/attack from known bad actor (HIGH)
    """
    import os

    log.info("Scanning Windows Firewall logs...")

    if not os.path.exists(FIREWALL_LOG):
        msg = (
            f"Firewall log not found: {FIREWALL_LOG}\n"
            "Enable logging: Windows Defender Firewall → Advanced Settings "
            "→ Properties → each Profile → Logging"
        )
        log.warning(msg)
        if callback:
            callback("WARNING: " + msg)
        return []

    hits = []
    cutoff = datetime.now() - timedelta(days=FIREWALL_LOG_DAYS)
    checked = set()

    conn = sqlite3.connect(DB_PATH)
    try:
        with open(FIREWALL_LOG, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                # Format: date time action protocol src-ip dst-ip src-port dst-port ...
                parts = line.split()
                if len(parts) < 6:
                    continue

                try:
                    log_time = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
                    if log_time < cutoff:
                        continue
                except ValueError:
                    continue

                action = parts[2].upper() if len(parts) > 2 else ""
                src_ip = parts[4] if len(parts) > 4 else ""
                dst_ip = parts[5] if len(parts) > 5 else ""

                if action not in ("ALLOW", "DROP"):
                    continue

                # --- Check destination IP (outbound / egress) ---
                if is_valid_ip(dst_ip) and not is_private_ip(dst_ip):
                    key = ("dst", dst_ip)
                    if key not in checked:
                        checked.add(key)
                        if is_ioc_known(dst_ip, "ip"):
                            if action == "DROP":
                                sev = "CRITICAL"
                                a_type = "MALICIOUS IP — BLOCKED BY FIREWALL (infection indicator)"
                                detail = (
                                    "A machine on this network attempted to connect to a known "
                                    "malicious IP and was blocked by the firewall. This strongly "
                                    "indicates an infected machine."
                                )
                            else:
                                sev = "CRITICAL"
                                a_type = "MALICIOUS IP IN FIREWALL LOG — ACTIVE OUTBOUND CONNECTION"
                                detail = (
                                    "An outbound connection to a known malicious IP was allowed "
                                    "through the firewall. Investigate immediately."
                                )
                            context = f"Firewall log — dst — action={action} at {parts[0]} {parts[1]}"
                            recorded = record_alert(
                                severity=sev,
                                alert_type=a_type,
                                ioc_value=dst_ip,
                                ioc_type="ip",
                                source_feed="firewall_scan",
                                context=context,
                                details=detail,
                                conn=conn,
                            )
                            conn.commit()
                            hit = {
                                "ioc": dst_ip,
                                "type": "ip",
                                "direction": "outbound",
                                "action": action,
                                "context": context,
                            }
                            hits.append(hit)
                            msg = f"[HIT] {dst_ip} (dst) — {action} — {'(new alert)' if recorded else '(dedupe)'}"
                            log.warning(msg)
                            if callback:
                                callback(msg)

                # --- Check source IP (inbound / ingress) ---
                if is_valid_ip(src_ip) and not is_private_ip(src_ip):
                    key = ("src", src_ip)
                    if key not in checked:
                        checked.add(key)
                        if is_ioc_known(src_ip, "ip"):
                            sev = "HIGH"
                            a_type = "MALICIOUS IP — INBOUND CONNECTION ATTEMPT"
                            detail = (
                                "A connection attempt was received from a known malicious IP. "
                                f"Action taken by firewall: {action}."
                            )
                            context = f"Firewall log — src — action={action} at {parts[0]} {parts[1]}"
                            recorded = record_alert(
                                severity=sev,
                                alert_type=a_type,
                                ioc_value=src_ip,
                                ioc_type="ip",
                                source_feed="firewall_scan",
                                context=context,
                                details=detail,
                                conn=conn,
                            )
                            conn.commit()
                            hit = {
                                "ioc": src_ip,
                                "type": "ip",
                                "direction": "inbound",
                                "action": action,
                                "context": context,
                            }
                            hits.append(hit)
                            msg = f"[HIT] {src_ip} (src) — {action} — {'(new alert)' if recorded else '(dedupe)'}"
                            log.warning(msg)
                            if callback:
                                callback(msg)

    except PermissionError:
        msg = "Cannot read firewall log — run as Administrator"
        log.error(msg)
        if callback:
            callback(f"ERROR: {msg}")
    except OSError as e:
        log.error("Error reading firewall log: %s", e)
        if callback:
            callback(f"ERROR reading firewall log: {e}")
    finally:
        conn.close()

    unique_ips = len({k[1] for k in checked})
    log.info("Firewall scan complete. %d unique IPs checked, %d malicious hits.", unique_ips, len(hits))
    if callback:
        callback(f"Firewall scan: {unique_ips} IPs checked, {len(hits)} malicious hits")
    return hits


# ---------------------------------------------------------------------------
#   DNS cache scanner
# ---------------------------------------------------------------------------


def scan_dns_cache(callback=None) -> list[dict]:
    """
    Read the Windows DNS resolver cache via PowerShell and check all domains
    against the threat intelligence database.
    """
    log.info("Scanning DNS cache...")
    hits = []

    try:
        ps_cmd = "Get-DnsClientCache | Select-Object -ExpandProperty Entry | Sort-Object -Unique"
        proc_result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc_result.returncode != 0 and proc_result.stderr:
            log.warning("PowerShell DNS cache stderr: %s", proc_result.stderr.strip())
        domains = [d.strip().lower() for d in proc_result.stdout.splitlines() if d.strip()]
    except Exception as e:
        log.error("Could not read DNS cache: %s", e)
        if callback:
            callback(f"ERROR reading DNS cache: {e}")
        return []

    checked = set()
    conn = sqlite3.connect(DB_PATH)
    try:
        for domain in domains:
            if not is_valid_domain(domain) or domain in checked:
                continue
            if is_whitelisted(domain, "domain"):
                continue

            checked.add(domain)

            if not is_ioc_known(domain, "domain"):
                continue

            context = "Found in Windows DNS resolver cache"
            recorded = record_alert(
                severity="CRITICAL",
                alert_type="MALICIOUS DOMAIN IN DNS CACHE",
                ioc_value=domain,
                ioc_type="domain",
                source_feed="dns_scan",
                context=context,
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
    except Exception as e:
        log.error("DNS scan error: %s", e)
    finally:
        conn.close()

    log.info("DNS scan complete. %d domains checked, %d hits.", len(checked), len(hits))
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

    FIX: IP extraction now restricted to lines starting with 'Received:'.
         Previously any line containing '[' was also searched, causing false
         positives from Message-ID headers and other bracketed fields.
    """
    lines = header_text.splitlines()
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    domain_pattern = re.compile(r"from\s+([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", re.IGNORECASE)

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

    # --- Extract IPs from Received: headers only (FIX: removed "[" in line branch) ---
    received_ips = []
    for line in lines:
        if line.lower().startswith("received:"):
            for ip in ip_pattern.findall(line):
                if is_valid_ip(ip) and not is_private_ip(ip):
                    received_ips.append(ip)

    # --- Extract domains from Received: headers ---
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
        report.append("  WARNING: From != Reply-To — possible phishing redirect!")

    unique_ips = list(dict.fromkeys(received_ips))
    unique_domains = list(dict.fromkeys(received_domains))[:50]  # raised from 20 to 50

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
                    "CRITICAL",
                    "MALICIOUS IP IN EMAIL HEADER",
                    ip,
                    "ip",
                    "email_analysis",
                    "Email header analysis",
                    "",
                    conn=conn,
                )
                conn.commit()
                report.append(f"  IP  {ip:<20} MALICIOUS")
            else:
                report.append(f"  IP  {ip:<20} Clean")

        for domain in unique_domains:
            if is_whitelisted(domain, "domain"):
                continue
            hit = is_ioc_known(domain, "domain")
            if hit:
                threat_count += 1
                record_alert(
                    "CRITICAL",
                    "MALICIOUS DOMAIN IN EMAIL HEADER",
                    domain,
                    "domain",
                    "email_analysis",
                    "Email header analysis",
                    "",
                    conn=conn,
                )
                conn.commit()
                report.append(f"  DOM {domain:<35} MALICIOUS")
            else:
                report.append(f"  DOM {domain:<35} Clean")
    except Exception as e:
        log.error("Email header analysis error: %s", e)
        report.append(f"  ERROR during analysis: {e}")
    finally:
        conn.close()

    report.append("-" * 60)
    if threat_count > 0 or mismatch_alert:
        report.append(f"  VERDICT: SUSPICIOUS — {threat_count} threat(s) detected")
        report.append("  Do NOT click links or open attachments in this email.")
    else:
        report.append("  VERDICT: No known threats found in email headers.")
        report.append("  Note: Clean headers don't guarantee the email is safe.")
    report.append("=" * 60)

    return "\n".join(report)
