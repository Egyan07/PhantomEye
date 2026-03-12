# =============================================================================
#   gui/theme.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Shared colour palette and reusable widget factory used by all tabs.
# =============================================================================

import tkinter as tk
from tkinter import ttk


# ---------------------------------------------------------------------------
#   Colour palette
# ---------------------------------------------------------------------------
BG        = "#0d1117"   # Near-black background
FG        = "#e6edf3"   # Light text
ACCENT    = "#2ea043"   # Green (OK / success)
ACCENT2   = "#1f6feb"   # Blue (action / selected)
WARN      = "#d29922"   # Yellow (warning)
DANGER    = "#f85149"   # Red (critical / threat)
PANEL     = "#161b22"   # Panel / card background
BORDER    = "#30363d"   # Border colour
ENTRY_BG  = "#21262d"   # Input field background
MUTED     = "#8b949e"   # Secondary / muted text


# ---------------------------------------------------------------------------
#   Widget factories
# ---------------------------------------------------------------------------

def make_button(parent, text: str, command, colour: str) -> tk.Button:
    return tk.Button(
        parent, text=text, command=command,
        bg=colour, fg="white",
        font=("Consolas", 10, "bold"),
        relief=tk.FLAT, padx=12, pady=5,
        activebackground=colour, activeforeground="white",
        cursor="hand2",
    )


def make_scrolled_text(parent, height: int = 14, readonly: bool = False) -> tk.Text:
    from tkinter import scrolledtext
    widget = scrolledtext.ScrolledText(
        parent,
        bg=PANEL, fg=FG,
        font=("Consolas", 10),
        height=height,
        insertbackground=FG,
        relief=tk.FLAT,
        borderwidth=1,
        wrap=tk.WORD,
    )
    if readonly:
        widget.config(state=tk.DISABLED)
    return widget


def make_label(parent, text: str, size: int = 10,
               colour: str = None, bold: bool = False) -> tk.Label:
    weight = "bold" if bold else "normal"
    return tk.Label(
        parent, text=text,
        bg=BG, fg=colour or MUTED,
        font=("Consolas", size, weight),
    )


def apply_treeview_style(tree: ttk.Treeview) -> None:
    """Apply the dark PhantomEye style to a Treeview widget."""
    style = ttk.Style()
    style.configure(
        "Treeview",
        background=PANEL, foreground=FG,
        fieldbackground=PANEL, rowheight=24,
        font=("Consolas", 10),
    )
    style.configure(
        "Treeview.Heading",
        background=ACCENT2, foreground="white",
        font=("Consolas", 10, "bold"),
    )
    style.map("Treeview", background=[("selected", ACCENT2)])
