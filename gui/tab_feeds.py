# =============================================================================
#   gui/tab_feeds.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Feed Status tab — shows IOC count, last update time, and status per feed.
# =============================================================================

import os
import sqlite3
import tkinter as tk
from tkinter import ttk

from config import DB_PATH, THREAT_FEEDS
from custom_feeds import add_custom_feed, load_custom_feeds, remove_custom_feed
from gui.theme import (
    ACCENT,
    ACCENT2,
    BG,
    DANGER,
    MUTED,
    WARN,
    apply_treeview_style,
    make_button,
)
from gui.tooltip import Tooltip


class FeedsTab:
    def __init__(self, parent: tk.Frame, run_update_fn) -> None:
        self.parent = parent
        self.run_update_fn = run_update_fn
        self._build()

    def _build(self) -> None:
        t = self.parent

        btn_row = tk.Frame(t, bg=BG)
        btn_row.pack(fill=tk.X, padx=15, pady=8)
        btn_update = make_button(btn_row, "⬇  Update All Feeds", self.run_update_fn, ACCENT2)
        btn_update.pack(side=tk.LEFT, padx=(0, 8))
        Tooltip(btn_update, "Download latest threat intelligence from all 8 feeds")

        btn_refresh = make_button(btn_row, "🔄 Refresh", self.refresh, "#444")
        btn_refresh.pack(side=tk.LEFT, padx=(0, 8))
        Tooltip(btn_refresh, "Reload feed status from database")

        btn_add = make_button(btn_row, "+  Add Feed", self._add_feed_dialog, ACCENT)
        btn_add.pack(side=tk.LEFT, padx=(0, 8))
        Tooltip(btn_add, "Add a custom threat feed URL")

        btn_remove = make_button(btn_row, "\u2212  Remove Feed", self._remove_feed, DANGER)
        btn_remove.pack(side=tk.LEFT)

        btn_export = make_button(btn_row, "  Export Blocklist", self._export_blocklist, ACCENT)
        btn_export.pack(side=tk.LEFT, padx=(8, 0))
        Tooltip(btn_export, "Export all malicious IPs as a firewall blocklist")
        Tooltip(btn_remove, "Remove selected custom feed")

        cols = ("Feed Name", "IOC Count", "Last Updated", "Status")
        widths = (330, 100, 180, 80)

        self.tree = ttk.Treeview(t, columns=cols, show="headings", height=12)
        apply_treeview_style(self.tree)

        for col, w in zip(cols, widths, strict=False):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")

        self.tree.tag_configure("ok", foreground=ACCENT)
        self.tree.tag_configure("failed", foreground=DANGER)
        self.tree.tag_configure("pending", foreground=WARN)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 6))

        self.total_label = tk.Label(t, text="", bg=BG, fg=MUTED, font=("Consolas", 10))
        self.total_label.pack(anchor="w", padx=15, pady=4)

        self.refresh()

    # -----------------------------------------------------------------------

    def _add_feed_dialog(self) -> None:
        from tkinter import messagebox, simpledialog

        url = simpledialog.askstring("Add Custom Feed", "Feed URL:", parent=self.parent)
        if not url or not url.startswith("http"):
            return
        label = simpledialog.askstring("Add Custom Feed", "Feed name/label:", parent=self.parent)
        if not label:
            return
        feed_type = simpledialog.askstring("Add Custom Feed", "Feed type (ip or domain):", parent=self.parent)
        if feed_type not in ("ip", "domain"):
            messagebox.showerror("PhantomEye", "Type must be 'ip' or 'domain'.")
            return
        feed_format = simpledialog.askstring(
            "Add Custom Feed",
            "Format (plain_ip, plain_domain, url_extract, feodo_csv, abuse_ssl_csv):",
            parent=self.parent,
        )
        valid_formats = ("plain_ip", "plain_domain", "url_extract", "feodo_csv", "abuse_ssl_csv")
        if feed_format not in valid_formats:
            messagebox.showerror("PhantomEye", f"Format must be one of: {', '.join(valid_formats)}")
            return
        result = add_custom_feed(label, url, feed_type, feed_format, label)
        if result:
            messagebox.showinfo("PhantomEye", f"Custom feed '{label}' added.\nClick 'Update All Feeds' to download it.")
            self.refresh()
        else:
            messagebox.showwarning("PhantomEye", "A feed with that name already exists.")

    def _remove_feed(self) -> None:
        from tkinter import messagebox

        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("PhantomEye", "Select a custom feed to remove.")
            return
        item = self.tree.item(selected[0])
        feed_label = item["values"][0]
        if not str(feed_label).startswith("[Custom]"):
            messagebox.showinfo("PhantomEye", "Only custom feeds can be removed.")
            return
        # Find the key
        custom = load_custom_feeds()
        key = None
        for k, v in custom.items():
            if v.get("label") == feed_label:
                key = k
                break
        if key and messagebox.askyesno("PhantomEye", f"Remove custom feed '{feed_label}'?"):
            remove_custom_feed(key)
            self.refresh()

    def _export_blocklist(self) -> None:
        from datetime import datetime
        from tkinter import filedialog, messagebox

        if not os.path.exists(DB_PATH):
            messagebox.showinfo("PhantomEye", "No database found. Update feeds first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"PhantomEye_Blocklist_{datetime.now().strftime('%Y%m%d')}.txt",
        )
        if not path:
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT DISTINCT value FROM iocs WHERE type='ip' ORDER BY value")
            ips = [row[0] for row in cur.fetchall()]
            conn.close()

            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# PhantomEye IP Blocklist \u2014 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
                f.write(f"# Total: {len(ips)} malicious IPs\n")
                f.write("# Import into your firewall or network appliance\n\n")
                for ip in ips:
                    f.write(ip + "\n")

            messagebox.showinfo("PhantomEye", f"Blocklist exported ({len(ips)} IPs):\n{path}")
        except Exception as e:
            messagebox.showerror("PhantomEye", f"Export failed: {e}")

    # -----------------------------------------------------------------------

    def refresh(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not os.path.exists(DB_PATH):
            for _feed_name, cfg in THREAT_FEEDS.items():
                self.tree.insert(
                    "",
                    tk.END,
                    values=(cfg["label"], "\u2014", "Not downloaded", "PENDING"),
                    tags=("pending",),
                )
            for _feed_name, cfg in load_custom_feeds().items():
                self.tree.insert(
                    "",
                    tk.END,
                    values=(cfg["label"], "\u2014", "Not downloaded", "PENDING"),
                    tags=("pending",),
                )
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()

            for feed_name, cfg in THREAT_FEEDS.items():
                cur.execute(
                    "SELECT ioc_count, last_updated, status FROM feed_status WHERE feed_name=?",
                    (feed_name,),
                )
                row = cur.fetchone()
                if row:
                    count, updated, status = row
                    tag = "ok" if status == "OK" else "failed"
                    self.tree.insert(
                        "",
                        tk.END,
                        values=(
                            cfg["label"],
                            f"{count:,}",
                            updated[:16] if updated else "—",
                            status,
                        ),
                        tags=(tag,),
                    )
                else:
                    self.tree.insert(
                        "",
                        tk.END,
                        values=(cfg["label"], "\u2014", "Not downloaded", "PENDING"),
                        tags=("pending",),
                    )

            # Custom feeds
            custom = load_custom_feeds()
            for feed_name, cfg in custom.items():
                cur.execute(
                    "SELECT ioc_count, last_updated, status FROM feed_status WHERE feed_name=?",
                    (feed_name,),
                )
                row = cur.fetchone()
                if row:
                    count, updated, status = row
                    tag = "ok" if status == "OK" else "failed"
                    self.tree.insert(
                        "",
                        tk.END,
                        values=(
                            cfg["label"],
                            f"{count:,}",
                            updated[:16] if updated else "\u2014",
                            status,
                        ),
                        tags=(tag,),
                    )
                else:
                    self.tree.insert(
                        "",
                        tk.END,
                        values=(cfg["label"], "\u2014", "Not downloaded", "PENDING"),
                        tags=("pending",),
                    )

            cur.execute("SELECT COUNT(*) FROM iocs")
            total = cur.fetchone()[0]
            conn.close()
            self.total_label.config(text=f"Total IOCs in database: {total:,}")
        except Exception as e:
            from logger import log

            log.warning("Feed status refresh error: %s", e)
