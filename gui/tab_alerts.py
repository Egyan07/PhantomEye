# =============================================================================
#   gui/tab_alerts.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Alert History tab with export-to-CSV support.
#
#   CHANGES v1.2:
#   - Alert history limit now pulled from config.ALERT_HISTORY_LIMIT
#     instead of hardcoded 500.
#   - Bare except: pass replaced with logged error.
# =============================================================================

import csv
import os
import sqlite3
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from config import ALERT_HISTORY_LIMIT, DB_PATH
from gui.theme import (
    ACCENT2,
    BG,
    DANGER,
    WARN,
    apply_treeview_style,
    make_button,
)


class AlertsTab:
    def __init__(self, parent: tk.Frame) -> None:
        self.parent = parent
        self._build()

    def _build(self) -> None:
        t = self.parent

        btn_row = tk.Frame(t, bg=BG)
        btn_row.pack(fill=tk.X, padx=15, pady=8)
        make_button(btn_row, "  Refresh", self.refresh, "#444").pack(side=tk.LEFT, padx=(0, 8))
        make_button(btn_row, "  Export CSV", self._export_csv, ACCENT2).pack(side=tk.LEFT, padx=(0, 8))
        make_button(btn_row, "Clear All Alerts", self._clear_alerts, DANGER).pack(side=tk.LEFT)

        # --- Treeview ---
        cols = ("Time", "Severity", "Type", "IOC", "Context")
        widths = (135, 80, 240, 160, 260)

        self.tree = ttk.Treeview(t, columns=cols, show="headings", height=18)
        apply_treeview_style(self.tree)

        for col, w in zip(cols, widths, strict=False):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")

        self.tree.tag_configure("critical", foreground=DANGER)
        self.tree.tag_configure("warning", foreground=WARN)

        scrollbar = ttk.Scrollbar(t, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(15, 0), pady=(0, 10))
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=(0, 10))

        self.refresh()

    # -----------------------------------------------------------------------

    def refresh(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        if not os.path.exists(DB_PATH):
            return
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute(
                """
                SELECT timestamp, severity, alert_type, ioc_value, context
                FROM alerts ORDER BY id DESC LIMIT ?
            """,
                (ALERT_HISTORY_LIMIT,),
            )
            for row in cur.fetchall():
                tag = "critical" if row[1] == "CRITICAL" else "warning"
                self.tree.insert("", tk.END, values=row, tags=(tag,))
            conn.close()
        except Exception as e:
            from logger import log

            log.warning("Alert history refresh error: %s", e)

    def _clear_alerts(self) -> None:
        if not messagebox.askyesno("PhantomEye", "Clear all alert history from database?"):
            return
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM alerts")
            conn.commit()
            conn.close()
            self.refresh()
        except Exception as e:
            messagebox.showerror("PhantomEye", f"Could not clear alerts: {e}")

    def _export_csv(self) -> None:
        if not os.path.exists(DB_PATH):
            messagebox.showinfo("PhantomEye", "No database found.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"PhantomEye_Alerts_{datetime.now().strftime('%Y%m%d')}.csv",
        )
        if not path:
            return
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute(
                "SELECT timestamp, severity, alert_type, ioc_value, ioc_type, "
                "source_feed, context, details FROM alerts ORDER BY id DESC"
            )
            rows = cur.fetchall()
            conn.close()

            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "Timestamp",
                        "Severity",
                        "Alert Type",
                        "IOC Value",
                        "IOC Type",
                        "Source Feed",
                        "Context",
                        "Details",
                    ]
                )
                writer.writerows(rows)

            messagebox.showinfo("PhantomEye", f"Exported {len(rows)} alerts to:\n{path}")
        except Exception as e:
            messagebox.showerror("PhantomEye", f"Export failed: {e}")
