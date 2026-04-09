# =============================================================================
#   gui/tab_lookup.py — PhantomEye v1.2
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

from gui.theme import (
    ACCENT,
    ACCENT2,
    BG,
    DANGER,
    ENTRY_BG,
    FG,
    MUTED,
    PANEL,
    make_button,
)
from gui.tooltip import Tooltip
from lookup import format_lookup_result, lookup_ioc


class LookupTab:
    def __init__(self, parent: tk.Frame, set_status_fn) -> None:
        self.parent = parent
        self.set_status = set_status_fn
        self._build()

    def _build(self) -> None:
        t = self.parent

        tk.Label(
            t,
            text="Enter any IP address or domain name to check against all threat feeds.",
            bg=BG,
            fg=MUTED,
            font=("Consolas", 10),
        ).pack(anchor="w", padx=15, pady=(12, 4))

        # --- Entry row ---
        entry_frame = tk.Frame(t, bg=BG)
        entry_frame.pack(fill=tk.X, padx=15, pady=4)

        self.entry = tk.Entry(
            entry_frame,
            bg=ENTRY_BG,
            fg=FG,
            font=("Consolas", 13),
            insertbackground=FG,
            relief=tk.FLAT,
            bd=6,
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.entry.bind("<Return>", lambda _e: self._do_lookup())

        _PLACEHOLDER = "e.g.  185.234.xxx.xxx  or  evil-domain.ru"
        self.entry.insert(0, _PLACEHOLDER)
        self.entry.bind(
            "<FocusIn>",
            lambda _e: self.entry.delete(0, tk.END) if "e.g." in self.entry.get() else None,
        )

        btn_lookup = make_button(entry_frame, "Lookup", self._do_lookup, ACCENT2)
        btn_lookup.pack(side=tk.LEFT)
        Tooltip(btn_lookup, "Check this IP or domain against all threat feeds")

        # --- Results box ---
        self.result_box = scrolledtext.ScrolledText(
            t,
            bg=PANEL,
            fg=FG,
            font=("Consolas", 11),
            height=20,
            relief=tk.FLAT,
            insertbackground=FG,
        )
        self.result_box.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        self.result_box.tag_config("danger", foreground=DANGER, font=("Consolas", 11, "bold"))
        self.result_box.tag_config("ok", foreground=ACCENT, font=("Consolas", 11, "bold"))
        self.result_box.insert(
            tk.END,
            "Paste an IP address or domain and press Lookup or hit Enter.\n\n"
            "Good for checking:\n"
            "  • Suspicious IPs from email headers\n"
            "  • Domains from suspicious links\n"
            "  • IPs from firewall alerts\n",
        )

        # --- Bulk Lookup ---
        tk.Label(
            t,
            text="Bulk Lookup \u2014 paste multiple IPs or domains (one per line):",
            bg=BG,
            fg=MUTED,
            font=("Consolas", 9),
        ).pack(anchor="w", padx=15, pady=(8, 2))

        bulk_frame = tk.Frame(t, bg=BG)
        bulk_frame.pack(fill=tk.X, padx=15, pady=(0, 4))

        self.bulk_input = scrolledtext.ScrolledText(
            bulk_frame,
            bg=ENTRY_BG,
            fg=FG,
            font=("Consolas", 10),
            height=5,
            relief=tk.FLAT,
            insertbackground=FG,
        )
        self.bulk_input.pack(fill=tk.X, pady=(0, 4))

        btn_bulk = make_button(bulk_frame, "  Bulk Lookup", self._do_bulk_lookup, ACCENT2)
        btn_bulk.pack(anchor="w")
        Tooltip(btn_bulk, "Check all IPs and domains against threat feeds")

    # -----------------------------------------------------------------------

    def _do_lookup(self) -> None:
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
            text = format_lookup_result(result)
            tag = "danger" if result["found"] else "ok"

            # Update GUI from the main thread
            self.parent.after(0, self._show_result, text, tag, value, result["found"])

        threading.Thread(target=task, daemon=True).start()

    def _show_result(self, text: str, tag: str, value: str, found: bool) -> None:
        self.result_box.config(state=tk.NORMAL)
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, text, tag)
        self.result_box.config(state=tk.DISABLED)
        verdict = "MALICIOUS" if found else "Clean"
        self.set_status(f"Lookup complete: {value} — {verdict}")

    # -----------------------------------------------------------------------
    #   Bulk lookup
    # -----------------------------------------------------------------------

    def _do_bulk_lookup(self) -> None:
        raw = self.bulk_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showinfo("PhantomEye", "Paste IPs or domains, one per line.")
            return

        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        if not lines:
            return

        self.set_status(f"Bulk lookup: {len(lines)} items...")
        self.result_box.config(state=tk.NORMAL)
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, f"Checking {len(lines)} items...\n\n")
        self.result_box.config(state=tk.DISABLED)

        def task():
            results = []
            for value in lines:
                result = lookup_ioc(value)
                verdict = "MALICIOUS" if result["found"] else "Clean"
                results.append((value, result["found"], verdict, result.get("type", "?")))

            self.parent.after(0, self._show_bulk_results, results)

        threading.Thread(target=task, daemon=True).start()

    def _show_bulk_results(self, results: list) -> None:
        self.result_box.config(state=tk.NORMAL)
        self.result_box.delete("1.0", tk.END)

        threats = sum(1 for _, found, _, _ in results if found)
        self.result_box.insert(tk.END, f"Bulk Lookup Results \u2014 {len(results)} checked, {threats} threats found\n")
        self.result_box.insert(tk.END, "=" * 55 + "\n\n")

        for value, found, verdict, ioc_type in results:
            tag = "danger" if found else "ok"
            self.result_box.insert(tk.END, f"  {ioc_type.upper():6}  {value:<40}  {verdict}\n", tag)

        self.result_box.insert(tk.END, "\n" + "=" * 55 + "\n")
        self.result_box.config(state=tk.DISABLED)
        self.set_status(f"Bulk lookup complete: {len(results)} checked, {threats} threats")
