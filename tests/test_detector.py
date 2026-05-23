"""
Unit tests for LogSentinel Detection Engine.
"""

import sys
import os
from datetime import datetime, timedelta
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models import LogEvent, Alert
from src.detector import DetectionEngine


class TestDetectionEngine:
    """Tests for the DetectionEngine class."""

    def setup_method(self):
        """Load rules for each test."""
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "rules.yaml")
        self.engine = DetectionEngine(config_path)

    def _make_event(self, source, event_type, ip="", user="", path="", status=0, timestamp=None):
        """Helper to create a LogEvent."""
        if timestamp is None:
            timestamp = datetime.now()
        parsed = {"event_type": event_type, "ip": ip}
        if user:
            parsed["user"] = user
        if path:
            parsed["path"] = path
        if status:
            parsed["status"] = status
        return LogEvent(
            timestamp=timestamp,
            source=source,
            raw="",
            parsed=parsed,
            host="server",
        )

    def test_load_rules(self):
        """Test that rules are loaded from YAML config."""
        assert len(self.engine.rules) == 7
        rule_ids = [r["rule_id"] for r in self.engine.rules]
        assert "DET-001" in rule_ids
        assert "DET-007" in rule_ids

    def test_ssh_brute_force_detection_det001(self):
        """DET-001: 5+ failed logins from same IP in 60s."""
        now = datetime.now()
        events = [
            self._make_event("auth.log", "failed_login", "10.0.0.5", "root", timestamp=now + timedelta(seconds=i))
            for i in range(6)
        ]
        alerts = self.engine.analyze_events(events)
        det001_alerts = [a for a in alerts if a.rule_id == "DET-001"]
        assert len(det001_alerts) == 1
        assert det001_alerts[0].source_ip == "10.0.0.5"
        assert det001_alerts[0].count >= 5

    def test_ssh_brute_force_below_threshold(self):
        """No alert if fewer than 5 failed logins."""
        now = datetime.now()
        events = [
            self._make_event("auth.log", "failed_login", "10.0.0.5", "root", timestamp=now + timedelta(seconds=i))
            for i in range(3)
        ]
        alerts = self.engine.analyze_events(events)
        det001_alerts = [a for a in alerts if a.rule_id == "DET-001"]
        assert len(det001_alerts) == 0

    def test_port_scan_detection_det002(self):
        """DET-002: 10+ connection attempts from same IP in 60s."""
        now = datetime.now()
        events = [
            self._make_event("auth.log", "connection", "10.0.0.99", timestamp=now + timedelta(seconds=i))
            for i in range(12)
        ]
        alerts = self.engine.analyze_events(events)
        det002_alerts = [a for a in alerts if a.rule_id == "DET-002"]
        assert len(det002_alerts) == 1
        assert det002_alerts[0].source_ip == "10.0.0.99"

    def test_sql_injection_detection_det003(self):
        """DET-003: SQL keywords in URL path."""
        event = self._make_event(
            "access.log", "", ip="1.2.3.4",
            path="/search?q=1'+OR+'1'%3D'1"
        )
        alerts = self.engine.analyze_events([event])
        det003_alerts = [a for a in alerts if a.rule_id == "DET-003"]
        assert len(det003_alerts) == 1
        assert det003_alerts[0].source_ip == "1.2.3.4"

    def test_xss_detection_det004(self):
        """DET-004: Script tags in URL path."""
        event = self._make_event(
            "access.log", "", ip="2.3.4.5",
            path="/comment?text=<script>alert('xss')</script>"
        )
        alerts = self.engine.analyze_events([event])
        det004_alerts = [a for a in alerts if a.rule_id == "DET-004"]
        assert len(det004_alerts) == 1
        assert det004_alerts[0].source_ip == "2.3.4.5"

    def test_xss_clean_request_no_alert(self):
        """Clean requests should not trigger XSS rule."""
        event = self._make_event(
            "access.log", "", ip="2.3.4.5",
            path="/about.html"
        )
        alerts = self.engine.analyze_events([event])
        det004_alerts = [a for a in alerts if a.rule_id == "DET-004"]
        assert len(det004_alerts) == 0

    def test_privilege_escalation_det005(self):
        """DET-005: Failed sudo followed by successful sudo."""
        now = datetime.now()
        events = [
            self._make_event(
                "auth.log", "sudo", "10.0.0.1", "bob",
                timestamp=now,
            ),
        ]
        # Add sudo_result manually
        events[0].parsed["sudo_result"] = "failed"
        events[0].parsed["message"] = "bob : user NOT in sudoers ; COMMAND=/bin/su"

        event2 = self._make_event(
            "auth.log", "sudo", "10.0.0.1", "bob",
            timestamp=now + timedelta(seconds=5),
        )
        event2.parsed["sudo_result"] = "success"
        event2.parsed["message"] = "bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/su"

        alerts = self.engine.analyze_events(events + [event2])
        det005_alerts = [a for a in alerts if a.rule_id == "DET-005"]
        assert len(det005_alerts) == 1

    def test_directory_traversal_det006(self):
        """DET-006: Directory traversal patterns in URL."""
        event = self._make_event(
            "access.log", "", ip="5.6.7.8",
            path="/../../etc/passwd"
        )
        alerts = self.engine.analyze_events([event])
        det006_alerts = [a for a in alerts if a.rule_id == "DET-006"]
        assert len(det006_alerts) == 1
        assert det006_alerts[0].source_ip == "5.6.7.8"

    def test_user_enumeration_det007(self):
        """DET-007: 3+ different usernames from same IP."""
        now = datetime.now()
        events = [
            self._make_event("auth.log", "failed_login", "10.0.0.5", user, timestamp=now + timedelta(seconds=i))
            for i, user in enumerate(["admin", "root", "bob", "alice"])
        ]
        alerts = self.engine.analyze_events(events)
        det007_alerts = [a for a in alerts if a.rule_id == "DET-007"]
        assert len(det007_alerts) == 1
        assert det007_alerts[0].source_ip == "10.0.0.5"

    def test_no_events_returns_empty(self):
        """Analyzing empty event list returns no alerts."""
        alerts = self.engine.analyze_events([])
        assert alerts == []

    def test_privilege_escalation_outside_window_det005(self):
        """DET-005: No alert if success happens outside the 300s time window."""
        now = datetime.now()
        events = [
            self._make_event(
                "auth.log", "sudo", "10.0.0.1", "bob",
                timestamp=now,
            ),
        ]
        events[0].parsed["sudo_result"] = "failed"
        events[0].parsed["message"] = "bob : user NOT in sudoers ; COMMAND=/bin/su"

        # Success 5 minutes later (300s) — boundary case, equal to window should still fire
        event2 = self._make_event(
            "auth.log", "sudo", "10.0.0.1", "bob",
            timestamp=now + timedelta(seconds=300),
        )
        event2.parsed["sudo_result"] = "success"
        event2.parsed["message"] = "bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/su"

        alerts = self.engine.analyze_events(events + [event2])
        det005_alerts = [a for a in alerts if a.rule_id == "DET-005"]
        # 300s is exactly at the boundary — "elapsed > time_window" means 300 > 300 = False, so fires
        assert len(det005_alerts) == 1, "Should fire when elapsed == time_window"

        # Success 301 seconds later — outside window
        event3 = self._make_event(
            "auth.log", "sudo", "10.0.0.1", "bob",
            timestamp=now + timedelta(seconds=301),
        )
        event3.parsed["sudo_result"] = "success"
        event3.parsed["message"] = "bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/su"

        alerts2 = self.engine.analyze_events([events[0], event3])
        det005_alerts2 = [a for a in alerts2 if a.rule_id == "DET-005"]
        assert len(det005_alerts2) == 0, "Should NOT fire when elapsed > time_window"
