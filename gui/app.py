# =============================================================================
#   gui/app.py — PhantomEye v1.2
#   Coded by Egyan | Red Parrot Accounting Ltd
#
#   Main application window.
#   Assembles all tabs and owns the header / status bar.
# =============================================================================

import tkinter as tk
from tkinter import ttk

from gui.tab_alerts import AlertsTab
from gui.tab_dashboard import DashboardTab
from gui.tab_email import EmailTab
from gui.tab_feeds import FeedsTab
from gui.tab_lookup import LookupTab
from gui.tab_monitor import MonitorTab
from gui.theme import ACCENT, ACCENT2, BG, FG, MUTED, PANEL


class PhantomEyeApp:
    """
    Main GUI window for PhantomEye v1.2.
    Coded by Egyan | Red Parrot Accounting Ltd
    """

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("👁  PhantomEye v2.0.0  |  Coded by Egyan  |  Red Parrot Accounting Ltd")
        self.root.geometry("1050x700")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)

        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        # Populate stats on open
        self.root.after(300, self.dashboard_tab.refresh)

        # Keyboard shortcuts
        self.root.bind("<F5>", lambda _e: self.dashboard_tab.refresh())
        self.root.bind("<Control-u>", lambda _e: self.dashboard_tab._run_update_feeds())
        self.root.bind("<Control-f>", lambda _e: self.dashboard_tab._run_firewall_scan())
        self.root.bind("<Control-d>", lambda _e: self.dashboard_tab._run_dns_scan())
        self.root.bind("<Control-Key-1>", lambda _e: self.notebook.select(0))
        self.root.bind("<Control-Key-2>", lambda _e: self.notebook.select(1))
        self.root.bind("<Control-Key-3>", lambda _e: self.notebook.select(2))
        self.root.bind("<Control-Key-4>", lambda _e: self.notebook.select(3))
        self.root.bind("<Control-Key-5>", lambda _e: self.notebook.select(4))
        self.root.bind("<Control-Key-6>", lambda _e: self.notebook.select(5))

    # -----------------------------------------------------------------------
    #   Header
    # -----------------------------------------------------------------------

    def _build_header(self) -> None:
        hdr = tk.Frame(self.root, bg=PANEL, height=55)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)

        tk.Label(
            hdr,
            text="👁  PhantomEye",
            font=("Consolas", 18, "bold"),
            bg=PANEL,
            fg=ACCENT,
        ).pack(side=tk.LEFT, padx=18, pady=10)

        tk.Label(
            hdr,
            text="Threat Intelligence Platform  |  Coded by Egyan  |  Red Parrot Accounting Ltd",
            font=("Consolas", 9),
            bg=PANEL,
            fg=MUTED,
        ).pack(side=tk.LEFT, pady=10)

    # -----------------------------------------------------------------------
    #   Tabs
    # -----------------------------------------------------------------------

    def _build_tabs(self) -> None:
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=PANEL,
            foreground=FG,
            font=("Consolas", 10),
            padding=[14, 6],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT2)],
            foreground=[("selected", "white")],
        )

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 0))

        # Create tab frames
        f_dashboard = tk.Frame(self.notebook, bg=BG)
        f_lookup = tk.Frame(self.notebook, bg=BG)
        f_email = tk.Frame(self.notebook, bg=BG)
        f_alerts = tk.Frame(self.notebook, bg=BG)
        f_feeds = tk.Frame(self.notebook, bg=BG)
        f_monitor = tk.Frame(self.notebook, bg=BG)

        self.notebook.add(f_dashboard, text=" Dashboard ")
        self.notebook.add(f_lookup, text=" IP / Domain Lookup ")
        self.notebook.add(f_email, text=" Email Header Analyser ")
        self.notebook.add(f_alerts, text=" Alert History ")
        self.notebook.add(f_feeds, text=" Feed Status ")
        self.notebook.add(f_monitor, text=" Connection Monitor ")

        # Instantiate tab controllers
        self.dashboard_tab = DashboardTab(f_dashboard)
        self.lookup_tab = LookupTab(f_lookup, self.set_status)
        self.email_tab = EmailTab(f_email, self.set_status)
        self.alerts_tab = AlertsTab(f_alerts)
        self.feeds_tab = FeedsTab(
            f_feeds,
            run_update_fn=self.dashboard_tab._run_update_feeds,
        )
        self.monitor_tab = MonitorTab(f_monitor)

        # Refresh alerts and feeds when their tabs are selected
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_change)

    # -----------------------------------------------------------------------
    #   Status bar
    # -----------------------------------------------------------------------

    def _build_status_bar(self) -> None:
        bar = tk.Frame(self.root, bg=PANEL)
        bar.pack(side=tk.BOTTOM, fill=tk.X)

        self._status_var = tk.StringVar(value="Ready — PhantomEye v2.0.0 | Red Parrot Accounting Ltd")
        tk.Label(
            bar,
            textvariable=self._status_var,
            bg=PANEL,
            fg=MUTED,
            font=("Consolas", 9),
            anchor="w",
            padx=10,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._clock_var = tk.StringVar()
        tk.Label(
            bar,
            textvariable=self._clock_var,
            bg=PANEL,
            fg=MUTED,
            font=("Consolas", 9),
            padx=10,
        ).pack(side=tk.RIGHT)

        self._update_clock()

    def set_status(self, msg: str) -> None:
        self._status_var.set(msg)
        self.root.update_idletasks()

    def _update_clock(self) -> None:
        from datetime import datetime

        self._clock_var.set(datetime.now().strftime("%H:%M:%S"))
        self.root.after(1000, self._update_clock)

    # -----------------------------------------------------------------------
    #   Tab switch handler
    # -----------------------------------------------------------------------

    def _on_tab_change(self, _event: tk.Event) -> None:
        selected = self.notebook.index(self.notebook.select())
        if selected == 3:  # Alert History
            self.alerts_tab.refresh()
        elif selected == 4:  # Feed Status
            self.feeds_tab.refresh()
