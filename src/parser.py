"""
LogSentinel - Log Parser

Parses SSH auth logs, Apache access logs, and syslog into unified LogEvent objects.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from .models import LogEvent

# ──────────────────────────────────────────────
# Regex Patterns
# ──────────────────────────────────────────────

# SSH auth.log pattern
# Example: May 21 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
SSH_PATTERN = re.compile(
    r"""
    (?P<month>\w{3})\s+
    (?P<day>\d{1,2})\s+
    (?P<time>\d{2}:\d{2}:\d{2})\s+
    (?P<host>\S+)\s+
    (?P<service>\S+?)(?:\[\d+\])?:\s+
    (?P<message>.+)
    """,
    re.VERBOSE,
)

# SSH failed login
SSH_FAILED_LOGIN = re.compile(r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)")

# SSH accepted login
SSH_ACCEPTED_LOGIN = re.compile(r"Accepted\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)")

# SSH connection
SSH_CONNECTION = re.compile(r"Connection\s+(?:from|closed)\s+(?P<ip>\S+)")

# Sudo attempts
SUDO_PATTERN = re.compile(r"(?P<user>\S+)\s+:.*?(?P<command>COMMAND=.*)$")
SUDO_FAILURE = re.compile(r"user\s+NOT\s+in\s+sudoers")

# Apache access.log pattern (combined log format)
# Example: 192.168.1.100 - - [21/May/2026:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
APACHE_PATTERN = re.compile(
    r"""
    (?P<ip>\S+)\s+\S+\s+\S+\s+
    \[(?P<timestamp>[^\]]+)\]\s+
    \"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)\"\s+
    (?P<status>\d{3})\s+
    (?P<size>\S+)\s+
    \"(?P<referer>[^\]]*)\"\s+
    \"(?P<user_agent>[^"]*)\"
    """,
    re.VERBOSE,
)

# Syslog pattern (similar to SSH but more generic)
SYSLOG_PATTERN = re.compile(
    r"""
    (?P<month>\w{3})\s+
    (?P<day>\d{1,2})\s+
    (?P<time>\d{2}:\d{2}:\d{2})\s+
    (?P<host>\S+)\s+
    (?P<service>\S+?)(?:\[\d+\])?:\s+
    (?P<message>.+)
    """,
    re.VERBOSE,
)

# Syslog iptables drop pattern
IPTABLES_DROP = re.compile(r"DPT=(?P<port>\d+).*SRC=(?P<src_ip>\S+).*DST=(?P<dst_ip>\S+)")

# ──────────────────────────────────────────────
# Date parsing utilities
# ──────────────────────────────────────────────

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_timestamp(month: str, day: str, time: str) -> datetime:
    """Parse syslog-style timestamp (e.g., 'May 21 10:30:45')."""
    now = datetime.now()
    year = now.year
    month_num = MONTH_MAP.get(month, 1)
    parts = time.split(":")
    hour, minute, second = int(parts[0]), int(parts[1]), int(parts[2])
    return datetime(year, month_num, int(day), hour, minute, second)


def _parse_apache_timestamp(ts: str) -> datetime:
    """Parse Apache log timestamp (e.g., '21/May/2026:10:30:45 +0000')."""
    # Format: 21/May/2026:10:30:45 +0000
    match = re.match(r"(\d+)/(\w+)/(\d+):(\d+:\d+:\d+)", ts)
    if not match:
        return datetime.now()
    day, month, year, time = match.groups()
    month_num = MONTH_MAP.get(month, 1)
    parts = time.split(":")
    hour, minute, second = int(parts[0]), int(parts[1]), int(parts[2])
    return datetime(int(year), month_num, int(day), hour, minute, second)


# ──────────────────────────────────────────────
# Log Source Detection
# ──────────────────────────────────────────────


def detect_log_source(line: str) -> Optional[str]:
    """Detect the log source type from a line of text."""
    # Apache logs start with an IP and contain a bracket timestamp
    if APACHE_PATTERN.match(line):
        return "access.log"
    # Syslog lines typically start with month name
    if SYSLOG_PATTERN.match(line):
        # Check for typical syslog services vs auth-specific
        m = SYSLOG_PATTERN.match(line)
        if m:
            service = m.group("service")
            if service in ("sshd", "sudo", "su"):
                return "auth.log"
            return "syslog"
    return None


# ──────────────────────────────────────────────
# Individual Parser Functions
# ──────────────────────────────────────────────


def parse_ssh_line(line: str) -> Optional[LogEvent]:
    """Parse a single line from auth.log (SSH/sudo entries)."""
    match = SSH_PATTERN.match(line)
    if not match:
        return None

    groups = match.groupdict()
    timestamp = _parse_syslog_timestamp(groups["month"], groups["day"], groups["time"])
    message = groups["message"]
    host = groups["host"]

    parsed: dict = {"service": groups["service"], "message": message}

    # Extract login details
    login_match = SSH_FAILED_LOGIN.search(message)
    if login_match:
        parsed["event_type"] = "failed_login"
        parsed["user"] = login_match.group("user")
        parsed["ip"] = login_match.group("ip")
    else:
        login_match = SSH_ACCEPTED_LOGIN.search(message)
        if login_match:
            parsed["event_type"] = "accepted_login"
            parsed["user"] = login_match.group("user")
            parsed["ip"] = login_match.group("ip")
        else:
            conn_match = SSH_CONNECTION.search(message)
            if conn_match:
                parsed["event_type"] = "connection"
                parsed["ip"] = conn_match.group("ip")
            else:
                sudo_match = SUDO_PATTERN.search(message)
                if sudo_match:
                    parsed["event_type"] = "sudo"
                    parsed["user"] = sudo_match.group("user")
                    parsed["command"] = sudo_match.group("command")
                    if SUDO_FAILURE.search(message):
                        parsed["sudo_result"] = "failed"
                    else:
                        parsed["sudo_result"] = "success"

    return LogEvent(
        timestamp=timestamp,
        source="auth.log",
        raw=line,
        parsed=parsed,
        host=host,
    )


def parse_apache_line(line: str) -> Optional[LogEvent]:
    """Parse a single line from Apache access.log."""
    match = APACHE_PATTERN.match(line)
    if not match:
        return None

    groups = match.groupdict()
    timestamp = _parse_apache_timestamp(groups["timestamp"])

    parsed: dict = {
        "ip": groups["ip"],
        "method": groups["method"],
        "path": groups["path"],
        "protocol": groups["protocol"],
        "status": int(groups["status"]),
        "size": groups["size"],
        "referer": groups["referer"],
        "user_agent": groups["user_agent"],
    }

    return LogEvent(
        timestamp=timestamp,
        source="access.log",
        raw=line,
        parsed=parsed,
        host="",
    )


def parse_syslog_line(line: str) -> Optional[LogEvent]:
    """Parse a single line from syslog."""
    match = SYSLOG_PATTERN.match(line)
    if not match:
        return None

    groups = match.groupdict()
    timestamp = _parse_syslog_timestamp(groups["month"], groups["day"], groups["time"])
    message = groups["message"]
    host = groups["host"]

    parsed: dict = {"service": groups["service"], "message": message}

    # Check for iptables drop events
    iptables_match = IPTABLES_DROP.search(message)
    if iptables_match:
        parsed["event_type"] = "iptables_drop"
        parsed["dst_port"] = iptables_match.group("port")
        parsed["src_ip"] = iptables_match.group("src_ip")
        parsed["dst_ip"] = iptables_match.group("dst_ip")

    return LogEvent(
        timestamp=timestamp,
        source="syslog",
        raw=line,
        parsed=parsed,
        host=host,
    )


# ──────────────────────────────────────────────
# Main Parse Function
# ──────────────────────────────────────────────


def parse_line(line: str, source_hint: Optional[str] = None) -> Optional[LogEvent]:
    """Parse a single log line, auto-detecting the source if not provided."""
    line = line.strip()
    if not line:
        return None

    source = source_hint or detect_log_source(line)

    if source == "auth.log":
        return parse_ssh_line(line)
    elif source == "access.log":
        return parse_apache_line(line)
    elif source == "syslog":
        return parse_syslog_line(line)

    return None


def parse_file(filepath: str, source_hint: Optional[str] = None) -> Generator[LogEvent, None, None]:
    """Parse an entire log file, yielding LogEvent objects."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line, source_hint)
            if event is not None:
                yield event
