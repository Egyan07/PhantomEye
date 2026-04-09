# =============================================================================
#   gui/tab_dashboard.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Dashboard tab: IOC stats, action buttons, console output.
#
#   FIXES v1.2:
#   - messagebox.showwarning() moved off background threads via after(0,...).
#     Calling tkinter GUI functions from daemon threads causes hangs/crashes.
#   - Feed health warning card added — turns red if any feed has failed.
#   - Last scan time now tracked and displayed in stats bar.
#   - Bare except: pass replaced with logged errors.
# =============================================================================

import os
import sqlite3
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

from config import DB_PATH
from feeds import check_stale_feeds, update_feeds
from gui.theme import (
    ACCENT,
    ACCENT2,
    BG,
    DANGER,
    MUTED,
    PANEL,
    WARN,
    make_button,
    make_scrolled_text,
)
from gui.tooltip import Tooltip
from scanner import scan_dns_cache, scan_firewall_logs


class DashboardTab:
    def __init__(self, parent: tk.Frame) -> None:
        self.parent = parent
        self._last_scan = "Never"
        self._build()

    def _build(self) -> None:
        t = self.parent

        # --- Stats row ---
        stats_frame = tk.Frame(t, bg=BG)
        stats_frame.pack(fill=tk.X, padx=15, pady=12)

        self.stat_iocs = self._stat_card(stats_frame, "Total IOCs", "0", ACCENT2)
        self.stat_alerts = self._stat_card(stats_frame, "Alerts Raised", "0", DANGER)
        self.stat_feeds = self._stat_card(stats_frame, "Feeds Active", "0", ACCENT)
        self.stat_updated = self._stat_card(stats_frame, "Last Updated", "Never", WARN)
        self.stat_scan = self._stat_card(stats_frame, "Last Scan", "Never", MUTED)

        # --- Action buttons ---
        btn_frame = tk.Frame(t, bg=BG)
        btn_frame.pack(fill=tk.X, padx=15, pady=(0, 8))

        btn_update = make_button(btn_frame, "  Update Feeds", self._run_update_feeds, ACCENT2)
        btn_update.pack(side=tk.LEFT, padx=4)
        Tooltip(btn_update, "Download latest threat intelligence from all 8 feeds")

        btn_fw = make_button(btn_frame, "  Scan Firewall Log", self._run_firewall_scan, ACCENT)
        btn_fw.pack(side=tk.LEFT, padx=4)
        Tooltip(btn_fw, "Check Windows Firewall log for malicious IP connections")

        btn_dns = make_button(btn_frame, "  Scan DNS Cache", self._run_dns_scan, ACCENT)
        btn_dns.pack(side=tk.LEFT, padx=4)
        Tooltip(btn_dns, "Check DNS resolver cache for malicious domain lookups")

        btn_refresh = make_button(btn_frame, "  Refresh", self.refresh, "#444")
        btn_refresh.pack(side=tk.LEFT, padx=4)
        Tooltip(btn_refresh, "Refresh dashboard statistics from database")

        # --- Progress bar (hidden until a long operation runs) ---
        self._progress_frame = tk.Frame(t, bg=BG)
        self._progress_frame.pack(fill=tk.X, padx=15, pady=(0, 4))
        self._progress_frame.pack_forget()  # hidden by default

        self._progress_label = tk.Label(self._progress_frame, text="", bg=BG, fg=MUTED, font=("Consolas", 9))
        self._progress_label.pack(anchor="w")

        style = ttk.Style()
        style.configure("green.Horizontal.TProgressbar", troughcolor=PANEL, background=ACCENT)
        self._progress_bar = ttk.Progressbar(
            self._progress_frame,
            style="green.Horizontal.TProgressbar",
            orient=tk.HORIZONTAL,
            length=400,
            mode="determinate",
        )
        self._progress_bar.pack(fill=tk.X, pady=(2, 0))

        # --- Feed health warning (hidden until a feed fails) ---
        self._health_var = tk.StringVar(value="")
        self._health_lbl = tk.Label(
            t,
            textvariable=self._health_var,
            bg=BG,
            fg=DANGER,
            font=("Consolas", 9),
        )
        self._health_lbl.pack(anchor="w", padx=15)

        # --- Console ---
        tk.Label(t, text="Console Output", bg=BG, fg=MUTED, font=("Consolas", 9)).pack(anchor="w", padx=15)
        self.console = make_scrolled_text(t, height=14)
        self.console.pack(fill=tk.BOTH, expand=True, padx=15, pady=(2, 10))
        self.console.tag_config("hit", foreground=DANGER)
        self.console.tag_config("ok", foreground=ACCENT)
        self.console.tag_config("info", foreground=MUTED)

        self._write(
            "PhantomEye v2.1.0 ready.\nClick 'Update Feeds' to download the latest threat intelligence.\n", "info"
        )

        # --- Keyboard shortcuts info ---
        shortcuts_frame = tk.Frame(t, bg=PANEL)
        shortcuts_frame.pack(fill=tk.X, padx=15, pady=(0, 8))
        shortcuts_text = (
            "Shortcuts:  F5 Refresh  |  Ctrl+U Update Feeds  |  Ctrl+F Firewall Scan  |  "
            "Ctrl+D DNS Scan  |  Ctrl+1-6 Switch Tabs"
        )
        tk.Label(shortcuts_frame, text=shortcuts_text, bg=PANEL, fg=MUTED, font=("Consolas", 8), padx=8, pady=4).pack(
            fill=tk.X
        )

    # -----------------------------------------------------------------------
    #   Public
    # -----------------------------------------------------------------------

    def refresh(self) -> None:
        """Refresh all stat cards from the database."""
        if not os.path.exists(DB_PATH):
            return
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
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
            self.stat_scan.config(text=self._last_scan[:10] if self._last_scan != "Never" else "Never")

            # Feed health check
            stale = check_stale_feeds()
            if stale:
                self._health_var.set(f"  WARNING: {len(stale)} feed(s) failed — click Update Feeds")
            else:
                self._health_var.set("")

        except Exception as e:
            from logger import log

            log.warning("Dashboard refresh error: %s", e)

    def write(self, msg: str, tag: str = "") -> None:
        self._write(msg, tag)

    # -----------------------------------------------------------------------
    #   Internal
    # -----------------------------------------------------------------------

    def _stat_card(self, parent: tk.Frame, label: str, value: str, colour: str, command=None) -> tk.Label:
        card = tk.Frame(parent, bg=PANEL, relief=tk.FLAT, bd=1)
        card.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)
        tk.Label(card, text=label, bg=PANEL, fg=MUTED, font=("Consolas", 9)).pack(pady=(8, 0))
        lbl = tk.Label(card, text=value, bg=PANEL, fg=colour, font=("Consolas", 20, "bold"))
        lbl.pack(pady=(0, 8))
        if command:
            card.config(cursor="hand2")
            card.bind("<Button-1>", lambda _e: command())
            lbl.bind("<Button-1>", lambda _e: command())
        return lbl

    def _write(self, msg: str, tag: str = "") -> None:
        self.console.config(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)

    def _run_update_feeds(self) -> None:
        def task():
            self._write("Starting feed update...", "info")
            # Show progress bar
            self.parent.after(0, self._show_progress, "Updating feeds...")

            from config import THREAT_FEEDS
            from custom_feeds import load_custom_feeds

            all_feeds = {**THREAT_FEEDS, **load_custom_feeds()}
            total_feeds = len(all_feeds)
            current = [0]  # mutable counter for closure

            def progress_callback(msg):
                self._write(msg, "info")
                if msg.strip().startswith(("Downloading:", "  ")):
                    current[0] += 0.5  # half per download, half per parse
                self.parent.after(
                    0,
                    self._update_progress,
                    int((current[0] / total_feeds) * 100),
                )

            try:
                update_feeds(callback=progress_callback)
                self._write("Feed update complete!", "ok")
                self.parent.after(0, self._hide_progress)
                self.parent.after(0, self.refresh)
            except Exception as e:
                self._write(f"Feed update error: {e}", "hit")
                self.parent.after(0, self._hide_progress)

        threading.Thread(target=task, daemon=True).start()

    def _show_progress(self, text: str) -> None:
        self._progress_label.config(text=text)
        self._progress_bar["value"] = 0
        self._progress_frame.pack(fill=tk.X, padx=15, pady=(0, 4))

    def _update_progress(self, value: int) -> None:
        self._progress_bar["value"] = min(value, 100)
        self._progress_label.config(text=f"Updating feeds... {min(value, 100)}%")

    def _hide_progress(self) -> None:
        self._progress_frame.pack_forget()

    def _run_firewall_scan(self) -> None:
        def task():
            self._write("Scanning Windows Firewall logs...", "info")
            hits = scan_firewall_logs(callback=lambda m: self._write(m, "hit" if "[HIT]" in m else "info"))
            self._last_scan = datetime.now().strftime("%Y-%m-%d %H:%M")
            self.parent.after(0, self.refresh)
            if hits:
                self._write(f"  {len(hits)} malicious IP(s) found in firewall log!", "hit")
                # FIX: messagebox must run on the main thread
                self.parent.after(
                    0,
                    lambda: messagebox.showwarning(
                        "PhantomEye — Threat Detected!",
                        f"{len(hits)} malicious IP connection(s) found.\nCheck the Alert History tab for details.",
                    ),
                )
            else:
                self._write("  No malicious IPs found in firewall log.", "ok")

        threading.Thread(target=task, daemon=True).start()

    def _run_dns_scan(self) -> None:
        def task():
            self._write("Scanning DNS cache...", "info")
            hits = scan_dns_cache(callback=lambda m: self._write(m, "hit" if "[HIT]" in m else "info"))
            self._last_scan = datetime.now().strftime("%Y-%m-%d %H:%M")
            self.parent.after(0, self.refresh)
            if hits:
                self._write(f"  {len(hits)} malicious domain(s) in DNS cache!", "hit")
                # FIX: messagebox must run on the main thread
                self.parent.after(
                    0,
                    lambda: messagebox.showwarning(
                        "PhantomEye — Threat Detected!",
                        f"{len(hits)} malicious domain(s) found in DNS cache.\n"
                        "A machine on your network recently resolved a known malicious domain.",
                    ),
                )
            else:
                self._write("  No malicious domains found in DNS cache.", "ok")

        threading.Thread(target=task, daemon=True).start()
