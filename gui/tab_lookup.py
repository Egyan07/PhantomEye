# =============================================================================
#   gui/tab_lookup.py — PhantomEye v1.1
#   Red Parrot Accounting Ltd
#
#   IP / Domain Lookup tab.
#
#   BUG FIX: lookup now runs in a daemon thread so it cannot block the GUI
#   thread.  v1.0 called lookup_ioc() directly on the main thread.
# =============================================================================

import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext

from lookup import lookup_ioc, format_lookup_result
from feeds import feeds_loaded
from gui.theme import (
    BG, FG, PANEL, ACCENT, ACCENT2, DANGER, MUTED, ENTRY_BG,
    make_button,
)


class LookupTab:
    def __init__(self, parent: tk.Frame, set_status_fn):
        self.parent     = parent
        self.set_status = set_status_fn
        self._build()

    def _build(self):
        t = self.parent

        tk.Label(
            t,
            text="Enter any IP address or domain name to check against all threat feeds.",
            bg=BG, fg=MUTED, font=("Consolas", 10),
        ).pack(anchor="w", padx=15, pady=(12, 4))

        # --- Entry row ---
        entry_frame = tk.Frame(t, bg=BG)
        entry_frame.pack(fill=tk.X, padx=15, pady=4)

        self.entry = tk.Entry(
            entry_frame,
            bg=ENTRY_BG, fg=FG,
            font=("Consolas", 13),
            insertbackground=FG,
            relief=tk.FLAT, bd=6,
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.entry.bind("<Return>", lambda _e: self._do_lookup())

        _PLACEHOLDER = "e.g.  185.234.xxx.xxx  or  evil-domain.ru"
        self.entry.insert(0, _PLACEHOLDER)
        self.entry.bind(
            "<FocusIn>",
            lambda _e: (
                self.entry.delete(0, tk.END)
                if "e.g." in self.entry.get()
                else None
            ),
        )

        make_button(entry_frame, "Lookup", self._do_lookup, ACCENT2).pack(side=tk.LEFT)

        # --- Results box ---
        self.result_box = scrolledtext.ScrolledText(
            t,
            bg=PANEL, fg=FG,
            font=("Consolas", 11),
            height=20,
            relief=tk.FLAT,
            insertbackground=FG,
        )
        self.result_box.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        self.result_box.tag_config(
            "danger", foreground=DANGER, font=("Consolas", 11, "bold")
        )
        self.result_box.tag_config(
            "ok", foreground=ACCENT, font=("Consolas", 11, "bold")
        )
        self.result_box.insert(
            tk.END,
            "Paste an IP address or domain and press Lookup or hit Enter.\n\n"
            "Good for checking:\n"
            "  • Suspicious IPs from email headers\n"
            "  • Domains from suspicious links\n"
            "  • IPs from firewall alerts\n",
        )

    # -----------------------------------------------------------------------

    def _do_lookup(self):
        value = self.entry.get().strip()
        if not value or "e.g." in value:
            messagebox.showinfo("PhantomEye", "Please enter an IP address or domain.")
            return

        self.set_status(f"Looking up: {value}...")
        self.result_box.config(state=tk.NORMAL)
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, f"Looking up: {value} ...\n")
        self.result_box.config(state=tk.DISABLED)

        def task():
            result = lookup_ioc(value)
            text   = format_lookup_result(result)
            tag    = "danger" if result["found"] else "ok"

            # Update GUI from the main thread
            self.parent.after(0, self._show_result, text, tag, value, result["found"])

        threading.Thread(target=task, daemon=True).start()

    def _show_result(self, text: str, tag: str, value: str, found: bool):
        self.result_box.config(state=tk.NORMAL)
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, text, tag)
        self.result_box.config(state=tk.DISABLED)
        verdict = "MALICIOUS" if found else "Clean"
        self.set_status(f"Lookup complete: {value} — {verdict}")
