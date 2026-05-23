"""
Unit tests for LogSentinel log parsers.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models import LogEvent
from src.parser import (
    parse_line,
    parse_ssh_line,
    parse_apache_line,
    parse_syslog_line,
    detect_log_source,
)


class TestSourceDetection:
    """Tests for log source auto-detection."""

    def test_detect_ssh_auth_log(self):
        line = "May 21 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        assert detect_log_source(line) == "auth.log"

    def test_detect_apache_access_log(self):
        line = '192.168.1.100 - - [21/May/2026:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        assert detect_log_source(line) == "access.log"

    def test_detect_syslog(self):
        line = "May 21 10:30:45 server kernel: [12345.678901] DROPPED IN=eth0 SRC=10.0.0.1 DST=10.0.0.2"
        assert detect_log_source(line) == "syslog"

    def test_detect_sudo_as_auth(self):
        line = "May 21 10:32:00 server sudo: john : TTY=pts/0 ; USER=root ; COMMAND=/bin/su -"
        assert detect_log_source(line) == "auth.log"

    def test_detect_empty_line(self):
        assert detect_log_source("") is None


class TestSSHParser:
    """Tests for SSH auth.log parsing."""

    def test_parse_failed_login(self):
        line = "May 21 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.source == "auth.log"
        assert event.parsed["event_type"] == "failed_login"
        assert event.parsed["user"] == "root"
        assert event.parsed["ip"] == "192.168.1.100"
        assert event.host == "server"

    def test_parse_failed_login_invalid_user(self):
        line = "May 21 10:31:00 server sshd[1235]: Failed password for invalid user admin from 10.0.0.5 port 22 ssh2"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.parsed["event_type"] == "failed_login"
        assert event.parsed["user"] == "admin"
        assert event.parsed["ip"] == "10.0.0.5"

    def test_parse_accepted_login(self):
        line = "May 21 10:31:00 server sshd[1234]: Accepted password for john from 192.168.1.200 port 22 ssh2"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.parsed["event_type"] == "accepted_login"
        assert event.parsed["user"] == "john"
        assert event.parsed["ip"] == "192.168.1.200"

    def test_parse_connection(self):
        line = "May 21 10:32:00 server sshd[1236]: Connection from 10.0.0.99 port 54321"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.parsed["event_type"] == "connection"
        assert event.parsed["ip"] == "10.0.0.99"

    def test_parse_sudo_success(self):
        line = "May 21 10:33:00 server sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/su -"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.parsed["event_type"] == "sudo"
        assert event.parsed["user"] == "john"
        assert event.parsed["sudo_result"] == "success"

    def test_parse_sudo_failure(self):
        line = "May 21 10:33:05 server sudo: bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/su -"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.parsed["event_type"] == "sudo"
        assert event.parsed["user"] == "bob"
        assert event.parsed["sudo_result"] == "failed"

    def test_parse_invalid_line(self):
        assert parse_ssh_line("this is not a valid log line") is None

    def test_timestamp_parsing(self):
        line = "May 21 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.timestamp.month == 5
        assert event.timestamp.day == 21
        assert event.timestamp.hour == 10
        assert event.timestamp.minute == 30
        assert event.timestamp.second == 45


class TestApacheParser:
    """Tests for Apache access.log parsing."""

    def test_parse_get_request(self):
        line = '192.168.1.100 - - [21/May/2026:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        event = parse_apache_line(line)
        assert event is not None
        assert event.source == "access.log"
        assert event.parsed["ip"] == "192.168.1.100"
        assert event.parsed["method"] == "GET"
        assert event.parsed["path"] == "/index.html"
        assert event.parsed["status"] == 200

    def test_parse_post_request(self):
        line = '10.0.0.5 - - [21/May/2026:14:22:10 +0000] "POST /login.php HTTP/1.1" 302 0 "http://example.com/login" "Mozilla/5.0"'
        event = parse_apache_line(line)
        assert event is not None
        assert event.parsed["method"] == "POST"
        assert event.parsed["path"] == "/login.php"
        assert event.parsed["status"] == 302

    def test_parse_sqli_pattern(self):
        line = '192.168.1.100 - - [21/May/2026:10:31:00 +0000] "GET /search?q=1%27+OR+%271%27%3D%271 HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
        event = parse_apache_line(line)
        assert event is not None
        assert event.parsed["path"] == "/search?q=1%27+OR+%271%27%3D%271"

    def test_parse_invalid_line(self):
        assert parse_apache_line("this is not a valid log line") is None


class TestSyslogParser:
    """Tests for syslog parsing."""

    def test_parse_kernel_message(self):
        line = "May 21 10:30:45 server kernel: [12345.678901] DROPPED IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.0.0.1 DST=10.0.0.2 LEN=60"
        event = parse_syslog_line(line)
        assert event is not None
        assert event.source == "syslog"
        assert event.parsed["service"] == "kernel"
        assert event.host == "server"

    def test_parse_invalid_line(self):
        assert parse_syslog_line("this is not a valid log line") is None


class TestParseLine:
    """Tests for the unified parse_line function."""

    def test_parse_with_source_hint(self):
        line = "May 21 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        event = parse_line(line, source_hint="auth.log")
        assert event is not None
        assert event.source == "auth.log"

    def test_parse_with_auto_detection(self):
        line = '192.168.1.100 - - [21/May/2026:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        event = parse_line(line)
        assert event is not None
        assert event.source == "access.log"

    def test_parse_empty_line(self):
        assert parse_line("") is None
        assert parse_line("   ") is None
