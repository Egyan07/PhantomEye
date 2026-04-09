# =============================================================================
#   gui/tab_monitor.py — PhantomEye v1.3
#   Coded by Egyan | Red Parrot Accounting Ltd
#
#   Real-time connection monitor tab.
#   Lists active TCP connections and highlights any that match IOC feeds.
# =============================================================================

import threading
import tkinter as tk
from tkinter import ttk

from gui.theme import (
    ACCENT,
    ACCENT2,
    BG,
    DANGER,
    MUTED,
    apply_treeview_style,
    make_button,
)
from gui.tooltip import Tooltip
from monitor import check_connections, get_active_connections


class MonitorTab:
    def __init__(self, parent: tk.Frame) -> None:
        self.parent = parent
        self._polling = False
        self._poll_interval = 10
        self._build()

    def _build(self) -> None:
        t = self.parent
        ctrl_frame = tk.Frame(t, bg=BG)
        ctrl_frame.pack(fill=tk.X, padx=15, pady=8)

        self._start_btn = make_button(ctrl_frame, "  Start Monitoring", self._toggle_monitoring, ACCENT)
        self._start_btn.pack(side=tk.LEFT, padx=(0, 8))
        Tooltip(self._start_btn, "Poll active connections every 10 seconds")

        btn_scan = make_button(ctrl_frame, "  Scan Now", self._scan_once, ACCENT2)
        btn_scan.pack(side=tk.LEFT, padx=(0, 8))
        Tooltip(btn_scan, "Check current connections against threat feeds")

        self._status_var = tk.StringVar(value="Monitoring: Stopped")
        tk.Label(
            ctrl_frame,
            textvariable=self._status_var,
            bg=BG,
            fg=MUTED,
            font=("Consolas", 10),
        ).pack(side=tk.LEFT, padx=10)

        self._threat_var = tk.StringVar(value="")
        tk.Label(
            t,
            textvariable=self._threat_var,
            bg=BG,
            fg=DANGER,
            font=("Consolas", 10, "bold"),
        ).pack(anchor="w", padx=15)

        cols = ("Remote IP", "Port", "State", "Status")
        widths = (200, 80, 120, 200)
        self.tree = ttk.Treeview(t, columns=cols, show="headings", height=16)
        apply_treeview_style(self.tree)
        for col, w in zip(cols, widths, strict=False):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("threat", foreground=DANGER)
        self.tree.tag_configure("safe", foreground=ACCENT)

        scrollbar = ttk.Scrollbar(t, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(15, 0), pady=(0, 10))
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=(0, 10))

    def _toggle_monitoring(self) -> None:
        if self._polling:
            self._polling = False
            self._start_btn.config(text="  Start Monitoring")
            self._status_var.set("Monitoring: Stopped")
        else:
            self._polling = True
            self._start_btn.config(text="  Stop Monitoring")
            self._status_var.set("Monitoring: Active")
            self._poll()

    def _poll(self) -> None:
        if not self._polling:
            return
        self._scan_once()
        self.parent.after(self._poll_interval * 1000, self._poll)

    def _scan_once(self) -> None:
        def task():
            connections = get_active_connections()
            threats = check_connections(connections)
            self.parent.after(0, self._update_tree, connections, threats)

        threading.Thread(target=task, daemon=True).start()

    def _update_tree(self, connections: list[dict], threats: list[dict]) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        threat_ips = {t["remote_ip"] for t in threats}
        for conn in connections:
            ip = conn["remote_ip"]
            if ip in threat_ips:
                tag = "threat"
                status = "MALICIOUS — IN THREAT DB"
            else:
                tag = "safe"
                status = "Clean"
            self.tree.insert(
                "",
                tk.END,
                values=(ip, conn["remote_port"], conn["state"], status),
                tags=(tag,),
            )
        if threats:
            self._threat_var.set(f"  {len(threats)} MALICIOUS connection(s) detected!")
        else:
            self._threat_var.set("")
        total = len(connections)
        self._status_var.set(
            f"Monitoring: {'Active' if self._polling else 'Stopped'} | {total} connections | {len(threats)} threats"
        )
