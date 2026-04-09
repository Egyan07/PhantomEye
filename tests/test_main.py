# =============================================================================
#   tests/test_main.py — PhantomEye v2.0
#   Red Parrot Accounting Ltd
#
#   Unit tests for main.py — CLI argument parsing, version, and banner output.
#   Run with: pytest tests/test_main.py -v
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from io import StringIO
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    db_path = str(tmp_path / "phantom_eye.db")
    with (
        patch("config.LOG_DIR", str(tmp_path)),
        patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
        patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
        patch("config.DB_PATH", db_path),
        patch("config.FIREWALL_LOG", str(tmp_path / "pfirewall.log")),
        patch("config.WHITELIST_IPS", []),
        patch("config.WHITELIST_DOMAINS", []),
    ):
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield tmp_path


from main import VERSION, _build_arg_parser, _print_banner

# ---------------------------------------------------------------------------
#   TestVersion
# ---------------------------------------------------------------------------


class TestVersion:
    def test_version_is_string(self):
        assert isinstance(VERSION, str)

    def test_version_format(self):
        """VERSION should follow semver-like X.Y.Z format."""
        assert VERSION.count(".") == 2
        parts = VERSION.split(".")
        assert all(p.isdigit() for p in parts)


# ---------------------------------------------------------------------------
#   TestArgParser
# ---------------------------------------------------------------------------


class TestArgParser:
    def test_gui_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--gui"])
        assert args.gui is True

    def test_update_feeds_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--update-feeds"])
        assert args.update_feeds is True

    def test_scan_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--scan"])
        assert args.scan is True

    def test_lookup_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--lookup", "1.2.3.4"])
        assert args.lookup == "1.2.3.4"

    def test_version_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--version"])
        assert args.version is True

    def test_check_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--check"])
        assert args.check is True

    def test_mutually_exclusive(self):
        """Passing two mutually exclusive flags should raise SystemExit."""
        parser = _build_arg_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--gui", "--scan"])

    def test_no_args_exits(self):
        """No arguments with the required group should raise SystemExit."""
        parser = _build_arg_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


# ---------------------------------------------------------------------------
#   TestPrintBanner
# ---------------------------------------------------------------------------


class TestPrintBanner:
    def test_banner_prints_version(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            _print_banner()
        output = buf.getvalue()
        assert VERSION in output

    def test_banner_prints_phantomeye(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            _print_banner()
        output = buf.getvalue()
        assert "PhantomEye" in output
