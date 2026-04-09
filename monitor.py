# =============================================================================
#   monitor.py — PhantomEye v1.3
#   Coded by Egyan | Red Parrot Accounting Ltd
#
#   Real-time connection monitor: parses netstat output to list active TCP
#   connections and checks remote IPs against the IOC threat database.
# =============================================================================

import re
import subprocess

from logger import log
from lookup import is_ioc_known
from utils import is_private_ip, is_valid_ip


def get_active_connections() -> list[dict]:
    """Parse active TCP connections from netstat -n."""
    try:
        result = subprocess.run(
            ["netstat", "-n", "-p", "TCP"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return _parse_netstat(result.stdout)
    except Exception as e:
        log.error("Could not run netstat: %s", e)
        return []


def _parse_netstat(output: str) -> list[dict]:
    """Parse netstat -n output into structured connection dicts."""
    connections = []
    for line in output.splitlines():
        line = line.strip()
        match = re.match(r"TCP\s+([\d.]+:\d+)\s+([\d.]+):(\d+)\s+(\w+)", line)
        if not match:
            continue
        local_addr = match.group(1)
        remote_ip = match.group(2)
        remote_port = match.group(3)
        state = match.group(4)
        if not is_valid_ip(remote_ip) or is_private_ip(remote_ip):
            continue
        connections.append(
            {
                "protocol": "TCP",
                "local_addr": local_addr,
                "remote_addr": f"{remote_ip}:{remote_port}",
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
            }
        )
    return connections


def check_connections(connections: list[dict]) -> list[dict]:
    """Check connections against IOC cache. Returns only threats."""
    threats = []
    seen: set[str] = set()
    for conn in connections:
        ip = conn["remote_ip"]
        if ip in seen:
            continue
        seen.add(ip)
        if is_ioc_known(ip, "ip"):
            conn["threat"] = True
            threats.append(conn)
    return threats
