"""
Unit tests for LogSentinel Alert Correlator.
"""

import sys
import os
from datetime import datetime, timedelta
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models import Alert, LogEvent, Report
from src.correlator import AlertCorrelator


def _make_alert(rule_id, severity, source_ip, count=1, statuses=None):
    """Helper to create an Alert for testing."""
    events = []
    if statuses:
        for status in statuses:
            events.append(LogEvent(
                timestamp=datetime.now(),
                source="access.log",
                raw="",
                parsed={"status": status},
                host="",
            ))
    else:
        events.append(LogEvent(
            timestamp=datetime.now(),
            source="auth.log",
            raw="",
            parsed={"ip": source_ip, "event_type": "failed_login"},
            host="server",
        ))

    return Alert(
        rule_id=rule_id,
        title=f"Alert {rule_id}",
        severity=severity,
        source_ip=source_ip,
        events=events * count if count > 1 else events,
        count=count,
        mitre_technique="",
        recommendation="",
        description="",
    )


class TestAlertCorrelator:
    """Tests for the AlertCorrelator class."""

    def setup_method(self):
        self.correlator = AlertCorrelator()

    def test_empty_alerts(self):
        """Empty alert list returns empty."""
        assert self.correlator.process([]) == []

    def test_single_alert_passthrough(self):
        """Single alert passes through unchanged."""
        alert = _make_alert("DET-001", "High", "10.0.0.5", count=5)
        result = self.correlator.process([alert])
        assert len(result) == 1
        assert result[0].rule_id == "DET-001"
        assert result[0].source_ip == "10.0.0.5"

    def test_deduplicate_same_rule_same_ip(self):
        """Multiple alerts with same rule and IP are merged into one."""
        now = datetime.now()
        alerts = [
            _make_alert("DET-001", "High", "10.0.0.5", count=6),
            _make_alert("DET-001", "High", "10.0.0.5", count=8),
        ]
        result = self.correlator.process(alerts)
        assert len(result) == 1
        assert result[0].count == 14  # merged count

    def test_separate_ips_not_merged(self):
        """Alerts from different IPs are not merged."""
        alerts = [
            _make_alert("DET-001", "High", "10.0.0.5"),
            _make_alert("DET-001", "High", "10.0.0.6"),
        ]
        result = self.correlator.process(alerts)
        assert len(result) == 2

    def test_severity_escalation_high_count(self):
        """High event count escalates severity."""
        alert = _make_alert("DET-001", "Low", "10.0.0.5", count=60)
        result = self.correlator.process([alert])
        assert result[0].severity == "Medium"  # escalated from Low

    def test_severity_escalation_very_high_count(self):
        """Very high event count escalates severity further."""
        alert = _make_alert("DET-001", "Low", "10.0.0.5", count=120)
        result = self.correlator.process([alert])
        assert result[0].severity == "High"  # escalated from Low (Low->Medium->High)

    def test_severity_stays_critical(self):
        """Critical severity stays critical regardless."""
        alert = _make_alert("DET-003", "Critical", "10.0.0.5", count=5)
        result = self.correlator.process([alert])
        assert result[0].severity == "Critical"

    def test_sql_execution_escalates_to_critical(self):
        """SQLi with successful response escalates to Critical."""
        alert = _make_alert("DET-003", "High", "10.0.0.5", statuses=[200])
        result = self.correlator.process([alert])
        assert result[0].severity == "Critical"

    def test_xss_with_success_escalates_to_critical(self):
        """XSS with successful response escalates to Critical."""
        alert = _make_alert("DET-004", "High", "10.0.0.5", statuses=[200])
        result = self.correlator.process([alert])
        assert result[0].severity == "Critical"

    def test_generate_report_empty(self):
        """Generate empty report with no alerts."""
        report = self.correlator.generate_report([], total_events=100)
        assert isinstance(report, Report)
        assert report.total_events == 100
        assert report.total_alerts == 0

    def test_generate_report_with_alerts(self):
        """Generate report with alerts and verify summary."""
        alerts = [
            _make_alert("DET-001", "High", "10.0.0.5"),
            _make_alert("DET-003", "Critical", "10.0.0.6"),
        ]
        report = self.correlator.generate_report(alerts, total_events=500, input_files=["auth.log"])
        assert report.total_alerts == 2
        assert report.total_events == 500
        assert "High" in report.summary["severity_breakdown"]
        assert "Critical" in report.summary["severity_breakdown"]
        assert "DET-001" in report.summary["rule_breakdown"]
