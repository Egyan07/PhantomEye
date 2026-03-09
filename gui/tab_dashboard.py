# =============================================================================
#   gui/tab_dashboard.py — PhantomEye v1.1
#   Red Parrot Accounting Ltd
#
#   Dashboard tab: IOC stats, action buttons, console output.
#
#   BUG FIX: _run_update_feeds, _run_firewall_scan, _run_dns_scan all
#   run in daemon threads (this was already correct in v1.0 — preserved).
# =============================================================================

import threading
import tkinter as tk
from tkinter import messagebox
from datetime import datetime

import sqlite3
import os

from config import DB_PATH
from feeds import update_feeds
from scanner import scan_firewall_logs, scan_dns_cache
from gui.theme import (
    BG, FG, PANEL, ACCENT, ACCENT2, WARN, DANGER, MUTED,
    make_button, make_scrolled_text,
)


class DashboardTab:
    def __init__(self, parent: tk.Frame):
        self.parent = parent
        self._build()

    def _build(self):
        t = self.parent

        # --- Stats row ---
        stats_frame = tk.Frame(t, bg=BG)
        stats_frame.pack(fill=tk.X, padx=15, pady=12)

        self.stat_iocs    = self._stat_card(stats_frame, "Total IOCs",    "0",     ACCENT2)
        self.stat_alerts  = self._stat_card(stats_frame, "Alerts Raised", "0",     DANGER)
        self.stat_feeds   = self._stat_card(stats_frame, "Feeds Active",  "0",     ACCENT)
        self.stat_updated = self._stat_card(stats_frame, "Last Updated",  "Never", WARN)

        # --- Action buttons ---
        btn_frame = tk.Frame(t, bg=BG)
        btn_frame.pack(fill=tk.X, padx=15, pady=(0, 8))

        make_button(btn_frame, "⬇  Update Feeds",      self._run_update_feeds,  ACCENT2).pack(side=tk.LEFT, padx=4)
        make_button(btn_frame, "🔍  Scan Firewall Log", self._run_firewall_scan, ACCENT ).pack(side=tk.LEFT, padx=4)
        make_button(btn_frame, "🌐  Scan DNS Cache",    self._run_dns_scan,      ACCENT ).pack(side=tk.LEFT, padx=4)
        make_button(btn_frame, "🔄  Refresh",           self.refresh,            "#444" ).pack(side=tk.LEFT, padx=4)

        # --- Console ---
        tk.Label(t, text="Console Output", bg=BG, fg=MUTED,
                 font=("Consolas", 9)).pack(anchor="w", padx=15)
        self.console = make_scrolled_text(t, height=14)
        self.console.pack(fill=tk.BOTH, expand=True, padx=15, pady=(2, 10))
        self.console.tag_config("hit",  foreground=DANGER)
        self.console.tag_config("ok",   foreground=ACCENT)
        self.console.tag_config("info", foreground=MUTED)

        self._write("PhantomEye v1.1 ready.\n"
                    "Click 'Update Feeds' to download the latest threat intelligence.\n",
                    "info")

    # -----------------------------------------------------------------------
    #   Public
    # -----------------------------------------------------------------------

    def refresh(self):
        """Refresh all stat cards from the database."""
        if not os.path.exists(DB_PATH):
            return
        try:
            conn = sqlite3.connect(DB_PATH)
            cur  = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM iocs")
            ioc_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM alerts")
            alert_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM feed_status WHERE status='OK'")
            feed_count = cur.fetchone()[0]
            cur.execute("SELECT MAX(last_updated) FROM feed_status WHERE status='OK'")
            last_upd = cur.fetchone()[0] or "Never"
            conn.close()

            self.stat_iocs.config(text=f"{ioc_count:,}")
            self.stat_alerts.config(text=str(alert_count))
            self.stat_feeds.config(text=str(feed_count))
            self.stat_updated.config(text=last_upd[:10] if last_upd else "Never")
        except Exception:
            pass

    def write(self, msg: str, tag: str = ""):
        self._write(msg, tag)

    # -----------------------------------------------------------------------
    #   Internal
    # -----------------------------------------------------------------------

    def _stat_card(self, parent, label: str, value: str, colour: str) -> tk.Label:
        card = tk.Frame(parent, bg=PANEL, relief=tk.FLAT, bd=1)
        card.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)
        tk.Label(card, text=label, bg=PANEL, fg=MUTED,
                 font=("Consolas", 9)).pack(pady=(8, 0))
        lbl = tk.Label(card, text=value, bg=PANEL, fg=colour,
                       font=("Consolas", 20, "bold"))
        lbl.pack(pady=(0, 8))
        return lbl

    def _write(self, msg: str, tag: str = ""):
        self.console.config(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)

    def _run_update_feeds(self):
        def task():
            self._write("Starting feed update...", "info")
            try:
                update_feeds(
                    callback=lambda m: self._write(m, "info")
                )
                self._write("Feed update complete!", "ok")
                self.refresh()
            except Exception as e:
                self._write(f"Error: {e}", "hit")
        threading.Thread(target=task, daemon=True).start()

    def _run_firewall_scan(self):
        def task():
            self._write("Scanning Windows Firewall logs...", "info")
            hits = scan_firewall_logs(
                callback=lambda m: self._write(
                    m, "hit" if "[HIT]" in m else "info"
                )
            )
            if hits:
                self._write(
                    f"⛔ {len(hits)} malicious IP(s) found in firewall log!", "hit"
                )
                messagebox.showwarning(
                    "PhantomEye — Threat Detected!",
                    f"{len(hits)} malicious IP connection(s) found.\n"
                    f"Check the Alert History tab for details."
                )
            else:
                self._write("✓ No malicious IPs found in firewall log.", "ok")
            self.refresh()
        threading.Thread(target=task, daemon=True).start()

    def _run_dns_scan(self):
        def task():
            self._write("Scanning DNS cache...", "info")
            hits = scan_dns_cache(
                callback=lambda m: self._write(
                    m, "hit" if "[HIT]" in m else "info"
                )
            )
            if hits:
                self._write(
                    f"⛔ {len(hits)} malicious domain(s) in DNS cache!", "hit"
                )
                messagebox.showwarning(
                    "PhantomEye — Threat Detected!",
                    f"{len(hits)} malicious domain(s) found in DNS cache.\n"
                    f"A machine on your network recently resolved a known malicious domain."
                )
            else:
                self._write("✓ No malicious domains found in DNS cache.", "ok")
            self.refresh()
        threading.Thread(target=task, daemon=True).start()
