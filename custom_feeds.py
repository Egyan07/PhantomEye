# =============================================================================
#   custom_feeds.py — PhantomEye v1.5
#   Red Parrot Accounting Ltd
#
#   Manages user-defined custom threat feeds stored in custom_feeds.json.
#   Custom feeds are loaded alongside the built-in 8 feeds and use the
#   same parsing pipeline.
# =============================================================================

import json
import os

from config import LOG_DIR
from logger import log

_CUSTOM_FEEDS_FILE = os.path.join(LOG_DIR, "custom_feeds.json")


def load_custom_feeds() -> dict[str, dict]:
    """Load custom feeds from JSON file. Returns dict matching THREAT_FEEDS format."""
    if not os.path.exists(_CUSTOM_FEEDS_FILE):
        return {}
    try:
        with open(_CUSTOM_FEEDS_FILE, encoding="utf-8") as f:
            feeds = json.load(f)
        if not isinstance(feeds, dict):
            return {}
        return feeds
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Could not load custom feeds: %s", e)
        return {}


def save_custom_feeds(feeds: dict[str, dict]) -> None:
    """Save custom feeds dict to JSON file."""
    try:
        os.makedirs(os.path.dirname(_CUSTOM_FEEDS_FILE), exist_ok=True)
        with open(_CUSTOM_FEEDS_FILE, "w", encoding="utf-8") as f:
            json.dump(feeds, f, indent=2)
        log.info("Custom feeds saved: %d feed(s)", len(feeds))
    except OSError as e:
        log.error("Could not save custom feeds: %s", e)


def add_custom_feed(name: str, url: str, feed_type: str, feed_format: str, label: str) -> bool:
    """Add a custom feed. Returns True on success."""
    feeds = load_custom_feeds()
    key = f"custom_{name.lower().replace(' ', '_')}"
    if key in feeds:
        return False
    feeds[key] = {
        "url": url,
        "type": feed_type,
        "format": feed_format,
        "label": f"[Custom] {label}",
    }
    save_custom_feeds(feeds)
    return True


def remove_custom_feed(key: str) -> bool:
    """Remove a custom feed by key. Returns True if found and removed."""
    feeds = load_custom_feeds()
    if key not in feeds:
        return False
    del feeds[key]
    save_custom_feeds(feeds)
    return True
