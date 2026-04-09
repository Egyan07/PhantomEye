# =============================================================================
#
#   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
#   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
#   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
#   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
#   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
#   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
#
#   ███████╗██╗   ██╗███████╗
#   ██╔════╝╚██╗ ██╔╝██╔════╝
#   █████╗   ╚████╔╝ █████╗
#   ██╔══╝    ╚██╔╝  ██╔══╝
#   ███████╗   ██║   ███████╗
#   ╚══════╝   ╚═╝   ╚══════╝
#
# =============================================================================
#   Tool    : PhantomEye v1.2
#   Author  : Coded by Egyan
#   Company : Red Parrot Accounting Ltd
#   Purpose : Threat Intelligence Platform — auto-checks your network against
#             known malware IPs, C2 servers, phishing domains, and spam senders.
#
#   Changelog v1.2:
#     - FIX: IPv6 validation rewritten with stdlib ipaddress module
#             (old regex had a character-class typo that rejected many valid IPs)
#     - FIX: messagebox calls in GUI moved off background threads (thread-safety)
#     - FIX: init_database/load_ioc_cache no longer called twice on --gui
#     - FIX: Empty lookup query returns explicit error instead of false "Clean"
#     - FIX: SMTP now uses ssl.create_default_context() (cert verification)
#     - FIX: Email IP extraction restricted to Received: headers only
#     - FIX: Firewall scanner now checks source IP (inbound attacks) too
#     - FIX: Double whitelist check in feed parser removed
#     - FIX: Bare except:pass replaced with logged warnings throughout
#     - NEW: _meta_cache in feeds.py — zero extra DB connections per lookup
#     - NEW: --version flag
#     - NEW: --check flag (config validation + feed health report)
#     - NEW: check_stale_feeds() used by --check and Dashboard health card
# =============================================================================

import argparse
import contextlib
import sys
import traceback

from alerts import record_alert
from database import init_database
from feeds import load_ioc_cache, update_feeds
from logger import log
from lookup import format_lookup_result, lookup_ioc
from scanner import scan_dns_cache, scan_firewall_logs

VERSION = "1.2"


def _print_banner() -> None:
    from datetime import datetime

    print()
    print("=" * 65)
    print(f"  PhantomEye v{VERSION}  —  Threat Intelligence Platform")
    print("  Coded by Egyan  |  Red Parrot Accounting Ltd")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)
    print()


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main",
        description=f"PhantomEye v{VERSION} — Threat Intelligence Platform\nCoded by Egyan | Red Parrot Accounting Ltd",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--gui", action="store_true", help="Launch the graphical dashboard")
    group.add_argument("--update-feeds", action="store_true", help="Download / refresh all threat feeds")
    group.add_argument("--scan", action="store_true", help="Run firewall + DNS scan (headless, for scheduled task)")
    group.add_argument(
        "--lookup", metavar="IP_OR_DOMAIN", help="Check a single IP or domain against the threat database"
    )
    group.add_argument("--version", action="store_true", help="Print version and exit")
    group.add_argument("--check", action="store_true", help="Validate config, DB connectivity, and feed health")
    return parser


def main() -> None:
    _print_banner()

    # No arguments → launch GUI directly (double-click / shortcut use)
    if len(sys.argv) < 2:
        _launch_gui()
        return

    parser = _build_arg_parser()
    args = parser.parse_args()

    if args.version:
        print(f"PhantomEye v{VERSION}")
        return

    if args.check:
        _run_check()
        return

    # All other modes need the DB
    init_database()

    if args.gui:
        load_ioc_cache()
        _launch_gui_no_reinit()

    elif args.update_feeds:
        log.info("Mode: --update-feeds")
        update_feeds()

    elif args.scan:
        log.info("Mode: --scan")
        load_ioc_cache()
        fw_hits = scan_firewall_logs()
        dns_hits = scan_dns_cache()
        total = len(fw_hits) + len(dns_hits)
        print(f"\nScan complete. {total} malicious IOC(s) detected.")
        if total > 0:
            print("Check the Alert History tab or database for details.")

    elif args.lookup:
        load_ioc_cache()
        result = lookup_ioc(args.lookup)
        print(format_lookup_result(result))


def _run_check() -> None:
    """
    Validate config, DB connectivity, and feed health.
    Exits with code 0 (all OK) or 1 (issues found).
    """
    import os

    from config import DB_PATH, FEEDS_DIR, FIREWALL_LOG, LOG_DIR, THREAT_FEEDS
    from feeds import check_stale_feeds

    issues = []
    print("PhantomEye Health Check")
    print("=" * 40)

    # Config paths
    for label, path in [("LOG_DIR", LOG_DIR), ("FEEDS_DIR", FEEDS_DIR)]:
        if os.path.isdir(path):
            print(f"  [OK] {label}: {path}")
        else:
            print(f"  [WARN] {label} not found: {path}")
            issues.append(f"{label} missing")

    if os.path.exists(FIREWALL_LOG):
        print(f"  [OK] Firewall log: {FIREWALL_LOG}")
    else:
        print(f"  [WARN] Firewall log not found: {FIREWALL_LOG}")
        print("         Enable logging in Windows Defender Firewall → Advanced Settings")
        issues.append("Firewall log missing")

    # DB connectivity
    try:
        init_database()
        print(f"  [OK] Database: {DB_PATH}")
    except Exception as e:
        print(f"  [FAIL] Database error: {e}")
        issues.append(f"DB error: {e}")

    # Feed health
    load_ioc_cache()
    stale = check_stale_feeds()
    if stale:
        print(f"  [WARN] {len(stale)} feed(s) failed or never downloaded:")
        for f in stale:
            print(f"         - {THREAT_FEEDS[f]['label']}")
        issues.append(f"{len(stale)} stale feeds")
    else:
        print(f"  [OK] All {len(THREAT_FEEDS)} feeds are up-to-date")

    from feeds import feeds_loaded, get_last_feed_time

    total = feeds_loaded()
    print(f"  [OK] IOCs in database: {total:,}")
    print(f"  [OK] Last feed update: {get_last_feed_time()}")

    print("=" * 40)
    if issues:
        print(f"Issues found: {len(issues)}")
        for i in issues:
            print(f"  - {i}")
        sys.exit(1)
    else:
        print("All checks passed.")
        sys.exit(0)


def _launch_gui() -> None:
    """Launch GUI after initialising DB and cache (called when no CLI args)."""
    import tkinter as tk

    from gui.app import PhantomEyeApp

    init_database()
    load_ioc_cache()

    root = tk.Tk()
    PhantomEyeApp(root)
    root.mainloop()


def _launch_gui_no_reinit() -> None:
    """
    Launch GUI when init_database/load_ioc_cache have already been called
    by main() — avoids the double-init that existed in v1.0/v1.1.
    """
    import tkinter as tk

    from gui.app import PhantomEyeApp

    root = tk.Tk()
    PhantomEyeApp(root)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("PhantomEye stopped by user.")
    except Exception as e:
        log.critical("PhantomEye crashed: %s", e)
        log.critical(traceback.format_exc())
        with contextlib.suppress(Exception):
            record_alert(
                "CRITICAL",
                "PHANTOMEYE CRASHED",
                "N/A",
                "system",
                "internal",
                "main.py",
                str(e),
            )
        sys.exit(1)
