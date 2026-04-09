# =============================================================================
#   tests/test_geolocation.py — PhantomEye v1.4
#   Red Parrot Accounting Ltd
#
#   Unit tests for geolocation.py — IP geolocation via ip-api.com.
#   Run with: pytest tests/test_geolocation.py -v
# =============================================================================

import json
import os
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from io import BytesIO
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    with (
        patch("config.LOG_DIR", str(tmp_path / "logs")),
        patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
        patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
        patch("config.DB_PATH", str(tmp_path / "phantom_eye.db")),
    ):
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield


from geolocation import geolocate_ip


def _make_response(data: dict) -> BytesIO:
    """Create a mock HTTP response body from a dict."""
    body = json.dumps(data).encode("utf-8")
    bio = BytesIO(body)
    bio.status = 200
    bio.read = bio.read
    return bio


class TestGeolocateIP:
    def test_successful_lookup(self):
        payload = {
            "status": "success",
            "country": "United Kingdom",
            "city": "London",
            "isp": "BT",
            "org": "BT Public Internet Service",
            "as": "AS2856 British Telecommunications PLC",
        }
        mock_resp = _make_response(payload)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None
        with patch("geolocation.urllib.request.urlopen", return_value=mock_resp):
            result = geolocate_ip("1.2.3.4")
        assert result is not None
        assert result["country"] == "United Kingdom"
        assert result["city"] == "London"
        assert result["isp"] == "BT"
        assert result["org"] == "BT Public Internet Service"
        assert result["as_number"] == "AS2856 British Telecommunications PLC"

    def test_failed_status(self):
        payload = {"status": "fail", "message": "reserved range"}
        mock_resp = _make_response(payload)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None
        with patch("geolocation.urllib.request.urlopen", return_value=mock_resp):
            result = geolocate_ip("192.168.1.1")
        assert result is None

    def test_timeout_returns_none(self):
        with patch(
            "geolocation.urllib.request.urlopen",
            side_effect=TimeoutError("timed out"),
        ):
            result = geolocate_ip("1.2.3.4")
        assert result is None

    def test_network_error_returns_none(self):
        with patch(
            "geolocation.urllib.request.urlopen",
            side_effect=urllib.error.URLError("network unreachable"),
        ):
            result = geolocate_ip("1.2.3.4")
        assert result is None

    def test_invalid_json_returns_none(self):
        bad_resp = BytesIO(b"not json at all")
        bad_resp.__enter__ = lambda s: s
        bad_resp.__exit__ = lambda s, *a: None
        with patch("geolocation.urllib.request.urlopen", return_value=bad_resp):
            result = geolocate_ip("1.2.3.4")
        assert result is None

    def test_missing_fields_use_defaults(self):
        payload = {"status": "success"}
        mock_resp = _make_response(payload)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None
        with patch("geolocation.urllib.request.urlopen", return_value=mock_resp):
            result = geolocate_ip("1.2.3.4")
        assert result is not None
        assert result["country"] == "Unknown"
        assert result["city"] == "Unknown"
        assert result["isp"] == "Unknown"
        assert result["org"] == "Unknown"
        assert result["as_number"] == "Unknown"
