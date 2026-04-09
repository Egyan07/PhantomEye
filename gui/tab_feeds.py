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
        btn_refresh.pack(side=tk.LEFT)
        Tooltip(btn_refresh, "Reload feed status from database")

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

    def refresh(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not os.path.exists(DB_PATH):
            for _feed_name, cfg in THREAT_FEEDS.items():
                self.tree.insert(
                    "",
                    tk.END,
                    values=(cfg["label"], "—", "Not downloaded", "PENDING"),
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
                        values=(cfg["label"], "—", "Not downloaded", "PENDING"),
                        tags=("pending",),
                    )

            cur.execute("SELECT COUNT(*) FROM iocs")
            total = cur.fetchone()[0]
            conn.close()
            self.total_label.config(text=f"Total IOCs in database: {total:,}")
        except Exception as e:
            from logger import log

            log.warning("Feed status refresh error: %s", e)
