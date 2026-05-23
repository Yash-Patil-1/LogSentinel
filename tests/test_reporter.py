"""
Unit tests for LogSentinel Reporter.
"""

import json
import os
import sys
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models import Alert, LogEvent, Report
from src.reporter import Reporter


class TestReporter:
    """Tests for the Reporter class."""

    def setup_method(self):
        """Create a temporary directory and sample report for each test."""
        self.tmp_dir = tempfile.mkdtemp()
        self.reporter = Reporter(output_dir=self.tmp_dir)

        # Create sample events
        events = [
            LogEvent(
                timestamp=datetime.now(),
                source="access.log",
                raw='GET /index.html HTTP/1.1',
                parsed={"ip": "10.0.0.5", "status": 200},
                host="server",
            ),
        ]

        # Create sample alerts
        self.alerts = [
            Alert(
                rule_id="DET-001",
                title="SSH Brute Force Attack",
                severity="High",
                source_ip="10.0.0.5",
                events=events,
                count=15,
                timestamp=datetime.now(),
                mitre_technique="T1110",
                recommendation="Block the source IP.",
                description="Multiple failed SSH login attempts.",
            ),
            Alert(
                rule_id="DET-003",
                title="SQL Injection Attempt",
                severity="Critical",
                source_ip="10.0.0.6",
                events=events,
                count=3,
                timestamp=datetime.now(),
                mitre_technique="T1190",
                recommendation="Use parameterized queries.",
                description="SQL keywords detected in URL.",
            ),
            Alert(
                rule_id="DET-007",
                title="User Enumeration Attempt",
                severity="Medium",
                source_ip="10.0.0.5",
                events=events,
                count=8,
                timestamp=datetime.now(),
                mitre_technique="T1589",
                recommendation="Rate-limit login attempts.",
                description="Multiple usernames tested.",
            ),
        ]

        # Build summary matching correlator output
        self.summary = {
            "total_alerts": 3,
            "severity_breakdown": {
                "Critical": 1,
                "High": 1,
                "Medium": 1,
            },
            "rule_breakdown": {
                "DET-001": 1,
                "DET-003": 1,
                "DET-007": 1,
            },
            "top_source_ips": [
                {"ip": "10.0.0.5", "alert_count": 2},
                {"ip": "10.0.0.6", "alert_count": 1},
            ],
        }

        self.report = Report(
            scan_time=datetime.now(),
            total_events=500,
            total_alerts=3,
            alerts=self.alerts,
            summary=self.summary,
            input_files=["auth.log", "access.log"],
        )

    def test_reporter_init(self):
        """Reporter creates output directory on init."""
        assert os.path.exists(self.tmp_dir)
        assert self.reporter.output_dir == self.tmp_dir

    def test_generate_json(self):
        """Generate JSON report and verify content."""
        path = self.reporter.generate_json(self.report, "test_report")
        assert path is not None
        assert os.path.exists(path)

        with open(path) as f:
            data = json.load(f)

        assert data["summary"]["total_alerts"] == 3
        assert data["summary"]["total_events"] == 500
        assert len(data["alerts"]) == 3
        assert data["alerts"][0]["rule_id"] == "DET-001"
        assert data["alerts"][1]["severity"] == "Critical"

    def test_generate_html(self):
        """Generate HTML report and verify it contains expected content."""
        path = self.reporter.generate_html(self.report, "test_report")
        assert path is not None
        assert os.path.exists(path)

        with open(path) as f:
            content = f.read()

        assert "LogSentinel Security Analysis Report" in content
        assert "DET-001" in content
        assert "Critical" in content
        assert "10.0.0.5" in content
        assert "T1110" in content
        assert "severity_pie" in content  # Chart should be referenced

    def test_generate_terminal(self):
        """Generate terminal report and verify content."""
        path = self.reporter.generate_terminal(self.report, "test_report")
        assert path is not None
        assert os.path.exists(path)

        with open(path) as f:
            content = f.read()

        assert "LOGSENTINEL" in content
        assert "DET-001" in content
        assert "SSH Brute Force" in content
        assert "10.0.0.5" in content

    def test_generate_all(self):
        """generate_all produces all three formats."""
        paths = self.reporter.generate_all(self.report, "test_all")
        assert "html" in paths
        assert "json" in paths
        assert "terminal" in paths
        for fmt, path in paths.items():
            assert os.path.exists(path), f"{fmt} report not found at {path}"

    def test_generate_json_empty_report(self):
        """Generate JSON from empty report (no alerts)."""
        empty = Report(total_events=100, total_alerts=0, alerts=[])
        path = self.reporter.generate_json(empty, "empty_report")
        assert path is not None

        with open(path) as f:
            data = json.load(f)
        assert data["summary"]["total_alerts"] == 0
        assert data["summary"]["total_events"] == 100
        assert len(data["alerts"]) == 0

    def test_generate_html_empty_report(self):
        """Generate HTML from empty report."""
        empty = Report(total_events=0, total_alerts=0, alerts=[])
        path = self.reporter.generate_html(empty, "empty_report")
        assert path is not None
        assert os.path.exists(path)

    def test_charts_generated(self):
        """Charts are created in the chart directory."""
        chart_dir = os.path.join(self.tmp_dir, "charts")
        charts = self.reporter._generate_charts(self.report, chart_dir)
        assert "severity_pie" in charts
        assert "rule_breakdown" in charts
        assert os.path.exists(charts["severity_pie"])
        assert os.path.exists(charts["rule_breakdown"])

    def test_report_to_dict(self):
        """Verify dict serialization structure."""
        data = self.reporter._report_to_dict(self.report)
        assert "report_metadata" in data
        assert data["report_metadata"]["tool"] == "LogSentinel"
        assert "summary" in data
        assert "alerts" in data
        assert len(data["alerts"]) == 3
        assert "events" in data["alerts"][0]
        assert "timestamp" in data["alerts"][0]
