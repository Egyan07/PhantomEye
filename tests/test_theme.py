# =============================================================================
#   tests/test_theme.py — PhantomEye v2.0
#   Red Parrot Accounting Ltd
#
#   Unit tests for gui/theme.py — colour constants and widget factory callables.
#   Since we run on WSL without a display, only non-GUI parts are tested.
#   Run with: pytest tests/test_theme.py -v
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    with (
        patch("config.LOG_DIR", str(tmp_path)),
        patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
        patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
    ):
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield


from gui.theme import (
    ACCENT,
    ACCENT2,
    BG,
    BORDER,
    DANGER,
    ENTRY_BG,
    FG,
    MUTED,
    PANEL,
    WARN,
    apply_treeview_style,
    make_button,
    make_label,
    make_scrolled_text,
)

ALL_COLORS = [BG, FG, ACCENT, ACCENT2, WARN, DANGER, PANEL, BORDER, ENTRY_BG, MUTED]


# ---------------------------------------------------------------------------
#   TestColorConstants
# ---------------------------------------------------------------------------


class TestColorConstants:
    def test_bg_is_hex(self):
        assert BG.startswith("#") and len(BG) == 7

    def test_fg_is_hex(self):
        assert FG.startswith("#") and len(FG) == 7

    def test_all_colors_are_hex(self):
        for color in ALL_COLORS:
            assert color.startswith("#") and len(color) == 7, f"Invalid color: {color}"

    def test_colors_are_distinct(self):
        assert len(set(ALL_COLORS)) == 10


# ---------------------------------------------------------------------------
#   TestWidgetFactories
# ---------------------------------------------------------------------------


class TestWidgetFactories:
    def test_make_button_is_callable(self):
        assert callable(make_button)

    def test_make_scrolled_text_is_callable(self):
        assert callable(make_scrolled_text)

    def test_make_label_is_callable(self):
        assert callable(make_label)

    def test_apply_treeview_style_is_callable(self):
        assert callable(apply_treeview_style)
