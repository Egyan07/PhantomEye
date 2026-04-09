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
    ENTRY_BG,
    FG,
    MUTED,
    PANEL,
    WARN,
    apply_treeview_style,
    make_button,
)
from gui.tooltip import Tooltip


class AlertsTab:
    def __init__(self, parent: tk.Frame) -> None:
        self.parent = parent
        self._build()

    def _build(self) -> None:
        t = self.parent

        btn_row = tk.Frame(t, bg=BG)
        btn_row.pack(fill=tk.X, padx=15, pady=8)
        btn_refresh = make_button(btn_row, "  Refresh", self.refresh, "#444")
        btn_refresh.pack(side=tk.LEFT, padx=(0, 8))
        Tooltip(btn_refresh, "Reload alert history from database")

        btn_csv = make_button(btn_row, "  Export CSV", self._export_csv, ACCENT2)
        btn_csv.pack(side=tk.LEFT, padx=(0, 8))
        Tooltip(btn_csv, "Save all alerts as a CSV spreadsheet")

        btn_html = make_button(btn_row, "  Export HTML", self._export_html, ACCENT2)
        btn_html.pack(side=tk.LEFT, padx=(0, 8))
        Tooltip(btn_html, "Generate a dark-themed HTML report")

        btn_clear = make_button(btn_row, "Clear All Alerts", self._clear_alerts, DANGER)
        btn_clear.pack(side=tk.LEFT)
        Tooltip(btn_clear, "Permanently delete all alert history")

        # --- Search bar ---
        search_frame = tk.Frame(t, bg=BG)
        search_frame.pack(fill=tk.X, padx=15, pady=(0, 4))
        tk.Label(search_frame, text="Search:", bg=BG, fg=MUTED, font=("Consolas", 9)).pack(side=tk.LEFT, padx=(0, 6))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._filter_alerts())
        self._search_entry = tk.Entry(
            search_frame,
            textvariable=self._search_var,
            bg=ENTRY_BG,
            fg=FG,
            font=("Consolas", 10),
            insertbackground=FG,
            relief=tk.FLAT,
            bd=4,
        )
        self._search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

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

        # --- Context menu ---
        self._context_menu = tk.Menu(t, tearoff=0, bg=PANEL, fg=FG, font=("Consolas", 9))
        self._context_menu.add_command(label="Copy IOC", command=self._copy_ioc)
        self._context_menu.add_command(label="Lookup IOC", command=self._lookup_ioc)
        self.tree.bind("<Button-3>", self._show_context_menu)

        self._all_alerts: list = []
        self.refresh()

    # -----------------------------------------------------------------------

    def refresh(self) -> None:
        self._all_alerts = []
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
            self._all_alerts = cur.fetchall()
            conn.close()
            self._display_alerts(self._all_alerts)
        except Exception as e:
            from logger import log

            log.warning("Alert history refresh error: %s", e)

    def _display_alerts(self, alerts: list) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for row in alerts:
            tag = "critical" if row[1] == "CRITICAL" else "warning"
            self.tree.insert("", tk.END, values=row, tags=(tag,))

    def _filter_alerts(self) -> None:
        query = self._search_var.get().lower().strip()
        if not query:
            self._display_alerts(self._all_alerts)
            return
        filtered = [row for row in self._all_alerts if any(query in str(field).lower() for field in row)]
        self._display_alerts(filtered)

    def _show_context_menu(self, event) -> None:
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self._context_menu.post(event.x_root, event.y_root)

    def _copy_ioc(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        ioc_value = self.tree.item(selected[0])["values"][3]  # IOC column
        self.parent.clipboard_clear()
        self.parent.clipboard_append(str(ioc_value))

    def _lookup_ioc(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        ioc_value = str(self.tree.item(selected[0])["values"][3])  # noqa: F841
        # Find the notebook and switch to lookup tab
        notebook = self.parent.master
        if hasattr(notebook, "select"):
            notebook.select(1)  # Lookup tab index

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

    def _export_html(self) -> None:
        if not os.path.exists(DB_PATH):
            messagebox.showinfo("PhantomEye", "No database found.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"PhantomEye_Report_{datetime.now().strftime('%Y%m%d')}.html",
        )
        if not path:
            return
        try:
            from reports import generate_alert_report

            count = generate_alert_report(path)
            messagebox.showinfo("PhantomEye", f"HTML report exported ({count} alerts):\n{path}")
        except Exception as e:
            messagebox.showerror("PhantomEye", f"Export failed: {e}")
