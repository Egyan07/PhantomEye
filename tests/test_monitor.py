# =============================================================================
#   tests/test_monitor.py — PhantomEye v1.3
#   Red Parrot Accounting Ltd
#
#   Unit tests for monitor.py — netstat parsing, IOC checking,
#   and subprocess error handling.
#   Run with: pytest tests/test_monitor.py -v
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_env(tmp_path):
    with (
        patch("config.LOG_DIR", str(tmp_path / "logs")),
        patch("config.FEEDS_DIR", str(tmp_path / "feeds")),
        patch("config.LOG_FILE", str(tmp_path / "phantom_eye.log")),
        patch("config.DB_PATH", str(tmp_path / "phantom_eye.db")),
        patch("config.WHITELIST_IPS", ["127.0.0.1"]),
        patch("config.WHITELIST_DOMAINS", ["microsoft.com"]),
    ):
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        os.makedirs(str(tmp_path / "feeds"), exist_ok=True)
        yield


from monitor import _parse_netstat, check_connections, get_active_connections

SAMPLE_NETSTAT = """\
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    192.168.1.10:54321     185.234.1.1:443        ESTABLISHED
  TCP    192.168.1.10:54322     8.8.8.8:443            ESTABLISHED
  TCP    192.168.1.10:54323     5.5.5.5:80             TIME_WAIT
  TCP    192.168.1.10:54324     10.0.0.1:8080          ESTABLISHED
  TCP    127.0.0.1:8080         127.0.0.1:54000        ESTABLISHED
"""


# ---------------------------------------------------------------------------
#   _parse_netstat
# ---------------------------------------------------------------------------


class TestParseNetstat:
    def test_parses_connections(self):
        """Should find exactly 3 public IP connections."""
        result = _parse_netstat(SAMPLE_NETSTAT)
        assert len(result) == 3
        ips = {c["remote_ip"] for c in result}
        assert ips == {"185.234.1.1", "8.8.8.8", "5.5.5.5"}

    def test_excludes_private_ips(self):
        """10.0.0.1 and 127.0.0.1 must be filtered out."""
        result = _parse_netstat(SAMPLE_NETSTAT)
        ips = {c["remote_ip"] for c in result}
        assert "10.0.0.1" not in ips
        assert "127.0.0.1" not in ips

    def test_extracts_fields(self):
        """Port, state, and protocol should be correctly extracted."""
        result = _parse_netstat(SAMPLE_NETSTAT)
        first = next(c for c in result if c["remote_ip"] == "185.234.1.1")
        assert first["remote_port"] == "443"
        assert first["state"] == "ESTABLISHED"
        assert first["protocol"] == "TCP"
        assert first["local_addr"] == "192.168.1.10:54321"
        assert first["remote_addr"] == "185.234.1.1:443"

    def test_empty_output(self):
        """Empty string should return empty list."""
        assert _parse_netstat("") == []

    def test_header_only(self):
        """Netstat output with only headers and no data rows."""
        header_only = """\
Active Connections

  Proto  Local Address          Foreign Address        State
"""
        assert _parse_netstat(header_only) == []


# ---------------------------------------------------------------------------
#   check_connections
# ---------------------------------------------------------------------------


class TestCheckConnections:
    def test_flags_malicious_connections(self):
        """Connections to known IOC IPs should be flagged as threats."""
        connections = [
            {"remote_ip": "185.234.1.1", "remote_port": "443", "state": "ESTABLISHED"},
            {"remote_ip": "8.8.8.8", "remote_port": "443", "state": "ESTABLISHED"},
        ]
        with patch("monitor.is_ioc_known", side_effect=lambda ip, _: ip == "185.234.1.1"):
            threats = check_connections(connections)
        assert len(threats) == 1
        assert threats[0]["remote_ip"] == "185.234.1.1"
        assert threats[0]["threat"] is True

    def test_deduplicates_ips(self):
        """Same IP appearing twice should only be checked once."""
        connections = [
            {"remote_ip": "185.234.1.1", "remote_port": "443", "state": "ESTABLISHED"},
            {"remote_ip": "185.234.1.1", "remote_port": "80", "state": "TIME_WAIT"},
        ]
        with patch("monitor.is_ioc_known", return_value=True) as mock_ioc:
            threats = check_connections(connections)
        assert len(threats) == 1
        # is_ioc_known should only be called once for the deduplicated IP
        mock_ioc.assert_called_once_with("185.234.1.1", "ip")

    def test_empty_connections(self):
        """Empty connection list should return empty threats."""
        with patch("monitor.is_ioc_known", return_value=False):
            assert check_connections([]) == []

    def test_no_threats(self):
        """When no IPs match IOCs, threats should be empty."""
        connections = [
            {"remote_ip": "8.8.8.8", "remote_port": "443", "state": "ESTABLISHED"},
            {"remote_ip": "1.1.1.1", "remote_port": "80", "state": "ESTABLISHED"},
        ]
        with patch("monitor.is_ioc_known", return_value=False):
            threats = check_connections(connections)
        assert threats == []


# ---------------------------------------------------------------------------
#   get_active_connections
# ---------------------------------------------------------------------------


class TestGetActiveConnections:
    def test_subprocess_error_returns_empty(self):
        """If netstat fails, return empty list without raising."""
        with patch("monitor.subprocess.run", side_effect=OSError("netstat not found")):
            result = get_active_connections()
        assert result == []

    def test_returns_parsed_connections(self):
        """Successful netstat run should return parsed connection list."""
        mock_result = MagicMock()
        mock_result.stdout = SAMPLE_NETSTAT
        with patch("monitor.subprocess.run", return_value=mock_result):
            result = get_active_connections()
        assert len(result) == 3
        ips = {c["remote_ip"] for c in result}
        assert "185.234.1.1" in ips
