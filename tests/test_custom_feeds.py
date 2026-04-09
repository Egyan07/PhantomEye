# =============================================================================
#   tests/test_custom_feeds.py — PhantomEye v1.5
#   Red Parrot Accounting Ltd
#
#   Unit tests for custom_feeds.py — custom feed CRUD operations.
#   Run with: pytest tests/test_custom_feeds.py -v
# =============================================================================

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    """Redirect all file I/O to a temp directory."""
    with (
        patch("config.LOG_DIR", str(tmp_path)),
        patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
        patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
        patch("custom_feeds.LOG_DIR", str(tmp_path)),
        patch("custom_feeds._CUSTOM_FEEDS_FILE", str(tmp_path / "custom_feeds.json")),
    ):
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield tmp_path


from custom_feeds import add_custom_feed, load_custom_feeds, remove_custom_feed, save_custom_feeds

# ---------------------------------------------------------------------------
#   load_custom_feeds
# ---------------------------------------------------------------------------


class TestLoadCustomFeeds:
    def test_no_file_returns_empty(self, tmp_path):
        result = load_custom_feeds()
        assert result == {}

    def test_loads_valid_json(self, tmp_path):
        feeds = {
            "custom_test": {
                "url": "http://example.com/feed.txt",
                "type": "ip",
                "format": "plain_ip",
                "label": "[Custom] Test",
            }
        }
        path = tmp_path / "custom_feeds.json"
        path.write_text(json.dumps(feeds), encoding="utf-8")
        result = load_custom_feeds()
        assert "custom_test" in result

    def test_invalid_json_returns_empty(self, tmp_path):
        path = tmp_path / "custom_feeds.json"
        path.write_text("not json", encoding="utf-8")
        result = load_custom_feeds()
        assert result == {}

    def test_non_dict_returns_empty(self, tmp_path):
        path = tmp_path / "custom_feeds.json"
        path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        result = load_custom_feeds()
        assert result == {}

    def test_permission_error_returns_empty(self, tmp_path):
        """PermissionError when opening the file should return empty dict."""
        path = tmp_path / "custom_feeds.json"
        path.write_text(json.dumps({"x": {}}), encoding="utf-8")
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            # load_custom_feeds checks os.path.exists first, so we need the file
            result = load_custom_feeds()
        assert result == {}

    def test_empty_file_returns_empty(self, tmp_path):
        """A file with empty string content should return empty dict."""
        path = tmp_path / "custom_feeds.json"
        path.write_text("", encoding="utf-8")
        result = load_custom_feeds()
        assert result == {}


# ---------------------------------------------------------------------------
#   save_custom_feeds
# ---------------------------------------------------------------------------


class TestSaveCustomFeeds:
    def test_saves_to_file(self, tmp_path):
        feeds = {"custom_x": {"url": "http://x.com", "type": "ip", "format": "plain_ip", "label": "[Custom] X"}}
        save_custom_feeds(feeds)
        path = tmp_path / "custom_feeds.json"
        assert path.exists()
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert "custom_x" in loaded


# ---------------------------------------------------------------------------
#   add_custom_feed
# ---------------------------------------------------------------------------


class TestAddCustomFeed:
    def test_adds_new_feed(self, tmp_path):
        result = add_custom_feed("My Feed", "http://example.com/feed.txt", "ip", "plain_ip", "My Feed")
        assert result is True
        feeds = load_custom_feeds()
        assert "custom_my_feed" in feeds
        assert feeds["custom_my_feed"]["label"] == "[Custom] My Feed"

    def test_duplicate_returns_false(self, tmp_path):
        add_custom_feed("Test", "http://a.com", "ip", "plain_ip", "Test")
        result = add_custom_feed("Test", "http://b.com", "ip", "plain_ip", "Test")
        assert result is False

    def test_key_generation(self, tmp_path):
        """Name 'My Test Feed' should generate key 'custom_my_test_feed'."""
        add_custom_feed("My Test Feed", "http://example.com", "ip", "plain_ip", "My Test Feed")
        feeds = load_custom_feeds()
        assert "custom_my_test_feed" in feeds

    def test_label_prefixed(self, tmp_path):
        """Added feed label should start with '[Custom]'."""
        add_custom_feed("Abc", "http://example.com", "ip", "plain_ip", "Abc")
        feeds = load_custom_feeds()
        assert feeds["custom_abc"]["label"].startswith("[Custom]")

    def test_preserves_existing(self, tmp_path):
        """Adding a second feed should not delete the first."""
        add_custom_feed("First", "http://first.com", "ip", "plain_ip", "First")
        add_custom_feed("Second", "http://second.com", "ip", "plain_ip", "Second")
        feeds = load_custom_feeds()
        assert "custom_first" in feeds
        assert "custom_second" in feeds


# ---------------------------------------------------------------------------
#   remove_custom_feed
# ---------------------------------------------------------------------------


class TestRemoveCustomFeed:
    def test_removes_existing(self, tmp_path):
        add_custom_feed("Test", "http://a.com", "ip", "plain_ip", "Test")
        result = remove_custom_feed("custom_test")
        assert result is True
        assert load_custom_feeds() == {}

    def test_nonexistent_returns_false(self, tmp_path):
        result = remove_custom_feed("custom_nonexistent")
        assert result is False
