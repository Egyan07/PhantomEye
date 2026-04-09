import tkinter as tk

from gui.theme import BORDER, FG, PANEL


class Tooltip:
    """Hover tooltip for any tkinter widget."""

    def __init__(self, widget: tk.Widget, text: str, delay: int = 500) -> None:
        self.widget = widget
        self.text = text
        self.delay = delay
        self._tip_window: tk.Toplevel | None = None
        self._after_id: str | None = None
        widget.bind("<Enter>", self._on_enter)
        widget.bind("<Leave>", self._on_leave)

    def _on_enter(self, _event) -> None:
        self._after_id = self.widget.after(self.delay, self._show)

    def _on_leave(self, _event) -> None:
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None
        self._hide()

    def _show(self) -> None:
        if self._tip_window:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self._tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=self.text,
            bg=PANEL,
            fg=FG,
            font=("Consolas", 9),
            relief=tk.SOLID,
            borderwidth=1,
            padx=8,
            pady=4,
            highlightbackground=BORDER,
        )
        label.pack()

    def _hide(self) -> None:
        if self._tip_window:
            self._tip_window.destroy()
            self._tip_window = None
