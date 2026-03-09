# =============================================================================
#   gui/tab_email.py — PhantomEye v1.1
#   Red Parrot Accounting Ltd
#
#   Email Header Analyser tab.
#
#   BUG FIX: analyse_email_headers() now runs in a daemon thread.
#   In v1.0 it ran on the main thread, which could freeze the GUI for
#   several seconds when checking 20+ extracted IPs and domains.
# =============================================================================

import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext

from scanner import analyse_email_headers
from gui.theme import (
    BG, FG, PANEL, ACCENT, ACCENT2, DANGER, MUTED, ENTRY_BG,
    make_button,
)


class EmailTab:
    def __init__(self, parent: tk.Frame, set_status_fn):
        self.parent     = parent
        self.set_status = set_status_fn
        self._build()

    def _build(self):
        t = self.parent

        tk.Label(
            t,
            text="Paste raw email headers to extract and check all sender IPs and domains.",
            bg=BG, fg=MUTED, font=("Consolas", 10),
        ).pack(anchor="w", padx=15, pady=(12, 4))
        tk.Label(
            t,
            text="In Outlook: Open email → File → Properties → copy Internet Headers box.",
            bg=BG, fg="#555", font=("Consolas", 9),
        ).pack(anchor="w", padx=15, pady=(0, 6))

        # --- Input ---
        tk.Label(t, text="Email Headers Input:", bg=BG, fg=MUTED,
                 font=("Consolas", 9)).pack(anchor="w", padx=15)

        self.input_box = scrolledtext.ScrolledText(
            t,
            bg=ENTRY_BG, fg=FG,
            font=("Consolas", 10),
            height=9,
            relief=tk.FLAT,
            insertbackground=FG,
        )
        self.input_box.pack(fill=tk.X, padx=15, pady=(2, 6))

        btn_row = tk.Frame(t, bg=BG)
        btn_row.pack(fill=tk.X, padx=15, pady=(0, 6))
        make_button(btn_row, "🔍  Analyse Headers", self._do_analysis, ACCENT2).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        make_button(
            btn_row, "Clear",
            lambda: self.input_box.delete("1.0", tk.END), "#444"
        ).pack(side=tk.LEFT)

        # --- Results ---
        tk.Label(t, text="Analysis Results:", bg=BG, fg=MUTED,
                 font=("Consolas", 9)).pack(anchor="w", padx=15)

        self.result_box = scrolledtext.ScrolledText(
            t,
            bg=PANEL, fg=FG,
            font=("Consolas", 10),
            height=9,
            relief=tk.FLAT,
            insertbackground=FG,
        )
        self.result_box.pack(fill=tk.BOTH, expand=True, padx=15, pady=(2, 10))
        self.result_box.tag_config("danger", foreground=DANGER)
        self.result_box.tag_config("ok",     foreground=ACCENT)

    # -----------------------------------------------------------------------

    def _do_analysis(self):
        headers = self.input_box.get("1.0", tk.END).strip()
        if not headers:
            messagebox.showinfo("PhantomEye", "Please paste email headers first.")
            return

        self.set_status("Analysing email headers...")
        self.result_box.config(state=tk.NORMAL)
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, "Analysing headers...\n")
        self.result_box.config(state=tk.DISABLED)

        def task():
            report = analyse_email_headers(headers)
            suspicious = any(
                kw in report
                for kw in ("SUSPICIOUS", "MALICIOUS", "WARNING")
            )
            tag = "danger" if suspicious else "ok"
            self.parent.after(0, self._show_result, report, tag)

        threading.Thread(target=task, daemon=True).start()

    def _show_result(self, report: str, tag: str):
        self.result_box.config(state=tk.NORMAL)
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, report, tag)
        self.result_box.config(state=tk.DISABLED)
        self.set_status("Email header analysis complete.")
