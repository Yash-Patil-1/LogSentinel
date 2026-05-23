"""
Integration tests for LogSentinel CLI pipeline.
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.main import run_pipeline, find_default_rules, find_sample_logs


class TestPipeline:
    """Integration tests for the full LogSentinel pipeline."""

    def setup_method(self):
        """Create a temporary output directory and locate sample logs and rules."""
        self.tmp_dir = tempfile.mkdtemp()
        self.rules_path = find_default_rules()
        assert self.rules_path is not None, "rules.yaml not found"

        # Locate sample logs
        sample_dir = Path(__file__).resolve().parent.parent / "sample_logs"
        self.auth_log = str(sample_dir / "auth.log")
        self.access_log = str(sample_dir / "access.log")
        self.syslog = str(sample_dir / "syslog")

    def test_find_sample_logs(self):
        """find_sample_logs returns bundled sample log paths."""
        samples = find_sample_logs()
        assert len(samples) >= 3
        assert any("auth.log" in s for s in samples)
        assert any("access.log" in s for s in samples)
        assert any("syslog" in s for s in samples)

    def test_pipeline_auth_log_only(self):
        """Run pipeline on auth.log only and verify alerts are generated."""
        paths = run_pipeline(
            log_files=[self.auth_log],
            rules_config=self.rules_path,
            output_dir=self.tmp_dir,
        )
        assert "html" in paths
        assert "json" in paths
        assert "terminal" in paths

        # Check JSON for expected alerts
        import json
        with open(paths["json"]) as f:
            data = json.load(f)
        assert data["summary"]["total_alerts"] > 0
        assert data["summary"]["total_events"] > 0

    def test_pipeline_access_log_only(self):
        """Run pipeline on access.log only."""
        paths = run_pipeline(
            log_files=[self.access_log],
            rules_config=self.rules_path,
            output_dir=self.tmp_dir,
        )
        assert "html" in paths

        import json
        with open(paths["json"]) as f:
            data = json.load(f)
        assert data["summary"]["total_alerts"] > 0

    def test_pipeline_syslog_only(self):
        """Run pipeline on syslog only (no detection rules target syslog, so alerts=0)."""
        paths = run_pipeline(
            log_files=[self.syslog],
            rules_config=self.rules_path,
            output_dir=self.tmp_dir,
        )
        assert "json" in paths

        import json
        with open(paths["json"]) as f:
            data = json.load(f)
        # Syslog has no matching rules in our config, so alerts should be 0
        assert data["summary"]["total_events"] > 0

    def test_pipeline_all_logs(self):
        """Run pipeline on all three sample log files."""
        paths = run_pipeline(
            log_files=[self.auth_log, self.access_log, self.syslog],
            rules_config=self.rules_path,
            output_dir=self.tmp_dir,
        )
        assert "html" in paths
        assert "json" in paths

        import json
        with open(paths["json"]) as f:
            data = json.load(f)
        assert data["summary"]["total_events"] > 0
        assert data["summary"]["total_alerts"] > 0

        # Verify HTML file is non-trivial
        with open(paths["html"]) as f:
            html = f.read()
        assert "LogSentinel" in html
        assert "Critical" in html or "High" in html

    def test_pipeline_nonexistent_file(self):
        """Run pipeline with a nonexistent file returns empty paths."""
        paths = run_pipeline(
            log_files=["/nonexistent/path.log"],
            rules_config=self.rules_path,
            output_dir=self.tmp_dir,
        )
        assert paths == {}

    def test_pipeline_empty_output_dir(self):
        """Pipeline creates output directory if it doesn't exist."""
        new_dir = os.path.join(self.tmp_dir, "nested", "output")
        paths = run_pipeline(
            log_files=[self.auth_log],
            rules_config=self.rules_path,
            output_dir=new_dir,
        )
        assert "html" in paths
        assert os.path.exists(new_dir)

    def test_find_default_rules(self):
        """Default rules config resolves to an existing file."""
        rules = find_default_rules()
        assert rules is not None
        assert os.path.exists(rules)
        assert rules.endswith("rules.yaml")
