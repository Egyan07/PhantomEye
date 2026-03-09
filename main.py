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
#   Tool    : PhantomEye v1.1
#   Author  : Coded by Egyan
#   Company : Red Parrot Accounting Ltd
#   Purpose : Threat Intelligence Platform — auto-checks your network against
#             known malware IPs, C2 servers, phishing domains, and spam senders.
#
#   Module layout:
#     main.py       — CLI entry point (this file)
#     config.py     — All user-editable configuration
#     logger.py     — Rotating log handler
#     database.py   — DB schema init
#     utils.py      — IP/domain validation, whitelist checks
#     feeds.py      — Feed download, parsing, in-memory IOC cache
#     lookup.py     — O(1) IOC lookup engine
#     alerts.py     — Alert dispatch with deduplication
#     scanner.py    — Firewall, DNS, and email header scan engines
#     gui/
#       app.py         — Main window (assembles all tabs)
#       theme.py       — Shared colour palette and widget helpers
#       tab_dashboard.py
#       tab_lookup.py
#       tab_email.py
#       tab_alerts.py
#       tab_feeds.py
#
#   Changelog v1.1:
#     - SPLIT into 14 modules (was 1,512-line single file)
#     - FIX: Lookup and email analysis now run in background threads
#             (v1.0 blocked the GUI thread)
#     - FIX: All scan loops share one DB connection passed into record_alert()
#             (v1.0 opened a new connection per alert)
#     - FIX: Firewall scanner now alerts on ALLOW *and* DROP entries
#             (v1.0 silently ignored blocked C2 connection attempts)
#     - FIX: Alert deduplication — same IOC won't re-alert within 24h
#     - FIX: Variable shadowing in scan_dns_cache (proc_result vs result)
#     - FIX: Zero-feeds warning shown in lookup results when DB is empty
#     - FIX: Email password read from PHANTOMEYE_EMAIL_PASSWORD env var
#     - FIX: IPv6 validation added (was silently skipped)
#     - FIX: CSV column detection for feodo/abuse_ssl feeds (survives
#             upstream format changes without silently skipping IOCs)
#     - FIX: Domain validation requires 2-char TLD (rejects "x.y")
#     - NEW: Export alerts to CSV from Alert History tab
# =============================================================================

import sys
import traceback

from logger  import log
from config  import LOG_FILE
from database import init_database
from feeds   import update_feeds, load_ioc_cache
from scanner import scan_firewall_logs, scan_dns_cache
from lookup  import lookup_ioc, format_lookup_result
from alerts  import record_alert


def _print_banner():
    from datetime import datetime
    print()
    print("=" * 65)
    print("  PhantomEye v1.1  —  Threat Intelligence Platform")
    print("  Coded by Egyan  |  Red Parrot Accounting Ltd")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)
    print()


def _build_arg_parser():
    import argparse
    parser = argparse.ArgumentParser(
        prog="main",
        description="PhantomEye v1.1 — Threat Intelligence Platform\n"
                    "Coded by Egyan | Red Parrot Accounting Ltd",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--gui", action="store_true",
        help="Launch the graphical dashboard"
    )
    group.add_argument(
        "--update-feeds", action="store_true",
        help="Download / refresh all threat feeds"
    )
    group.add_argument(
        "--scan", action="store_true",
        help="Run firewall + DNS scan (headless, for scheduled task)"
    )
    group.add_argument(
        "--lookup", metavar="IP_OR_DOMAIN",
        help="Check a single IP or domain against the threat database"
    )
    return parser


def main():
    _print_banner()

    # No arguments → launch GUI directly
    if len(sys.argv) < 2:
        _launch_gui()
        return

    parser = _build_arg_parser()
    args   = parser.parse_args()

    init_database()

    if args.gui:
        load_ioc_cache()
        _launch_gui()

    elif args.update_feeds:
        log.info("Mode: --update-feeds")
        update_feeds()

    elif args.scan:
        log.info("Mode: --scan")
        load_ioc_cache()
        fw_hits  = scan_firewall_logs()
        dns_hits = scan_dns_cache()
        total    = len(fw_hits) + len(dns_hits)
        print(f"\nScan complete. {total} malicious IOC(s) detected.")
        if total > 0:
            print("Check the Alert History tab or database for details.")

    elif args.lookup:
        load_ioc_cache()
        result = lookup_ioc(args.lookup)
        print(format_lookup_result(result))


def _launch_gui():
    import tkinter as tk
    from gui.app import PhantomEyeApp

    init_database()
    load_ioc_cache()

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
        try:
            record_alert(
                "CRITICAL", "PHANTOMEYE CRASHED", "N/A", "system",
                "internal", "main.py", str(e),
            )
        except Exception:
            pass
        sys.exit(1)
