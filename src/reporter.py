"""
LogSentinel - Reporter

Generates professional security reports in multiple formats:
  - HTML with embedded matplotlib charts
  - JSON for machine processing
  - Colorized terminal output
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server/CLI use
import matplotlib.pyplot as plt

from jinja2 import Environment, PackageLoader, FileSystemLoader

from .models import Alert, Report

# Severity colors for consistent styling
SEVERITY_COLORS = {
    "Critical": "#dc3545",  # Red
    "High": "#fd7e14",      # Orange
    "Medium": "#ffc107",    # Yellow
    "Low": "#28a745",       # Green
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


class Reporter:
    """Generates security reports in HTML, JSON, and terminal formats."""

    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize the reporter.

        Args:
            output_dir: Directory to save generated reports and charts.
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_all(
        self,
        report: Report,
        report_name: Optional[str] = None,
    ) -> dict[str, str]:
        """
        Generate all report formats.

        Args:
            report: The Report object to render.
            report_name: Optional base name for output files.

        Returns:
            Dict with keys 'html', 'json', 'terminal' mapping to file paths.
        """
        if report_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_name = f"logsentinel_report_{timestamp}"

        paths = {}

        html_path = self.generate_html(report, report_name)
        if html_path:
            paths["html"] = html_path

        json_path = self.generate_json(report, report_name)
        if json_path:
            paths["json"] = json_path

        terminal_path = self.generate_terminal(report, report_name)
        if terminal_path:
            paths["terminal"] = terminal_path

        return paths

    def generate_html(
        self,
        report: Report,
        report_name: str = "logsentinel_report",
    ) -> Optional[str]:
        """
        Generate an HTML report with embedded charts.

        Args:
            report: The Report object to render.
            report_name: Base name for the output file.

        Returns:
            Path to the generated HTML file, or None on failure.
        """
        try:
            # Generate charts into subdirectory
            chart_dir = os.path.join(self.output_dir, "charts")
            charts = self._generate_charts(report, chart_dir)

            # Convert absolute chart paths to relative paths for HTML portability
            rel_charts = {}
            for key, path in charts.items():
                rel_charts[key] = os.path.relpath(path, self.output_dir)

            # Load Jinja2 template
            template_dir = os.path.join(os.path.dirname(__file__), "templates")
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template("report.html")

            # Build template context
            severity_counts = report.summary.get("severity_breakdown", {})
            rule_breakdown = report.summary.get("rule_breakdown", {})
            top_ips = report.summary.get("top_source_ips", [])

            context = {
                "report_title": "LogSentinel Security Analysis Report",
                "scan_time": report.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_events": report.total_events,
                "total_alerts": report.total_alerts,
                "input_files": report.input_files,
                "severity_counts": severity_counts,
                "rule_breakdown": rule_breakdown,
                "top_ips": top_ips,
                "alerts": report.alerts,
                "charts": rel_charts,
                "severity_colors": SEVERITY_COLORS,
                "severity_order": SEVERITY_ORDER,
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            html_content = template.render(**context)

            output_path = os.path.join(self.output_dir, f"{report_name}.html")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            return output_path

        except Exception as e:
            print(f"Warning: HTML report generation failed: {e}")
            return None

    def generate_json(
        self,
        report: Report,
        report_name: str = "logsentinel_report",
    ) -> Optional[str]:
        """
        Generate a JSON report.

        Args:
            report: The Report object to serialize.
            report_name: Base name for the output file.

        Returns:
            Path to the generated JSON file, or None on failure.
        """
        try:
            data = self._report_to_dict(report)

            output_path = os.path.join(self.output_dir, f"{report_name}.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)

            return output_path

        except Exception as e:
            print(f"Warning: JSON report generation failed: {e}")
            return None

    def generate_terminal(
        self,
        report: Report,
        report_name: str = "logsentinel_report",
        print_output: bool = False,
    ) -> Optional[str]:
        """
        Generate a colorized terminal-friendly text report.

        Args:
            report: The Report object to render.
            report_name: Base name for the output file.
            print_output: If True, also print the report to stdout.

        Returns:
            Path to the generated text file, or None on failure.
        """
        try:
            lines: list[str] = []

            # Header
            lines.append("=" * 70)
            lines.append("  LOGSENTINEL - Security Analysis Report")
            lines.append("=" * 70)
            lines.append(f"")
            lines.append(f"  Scan Time:     {report.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"  Total Events:  {report.total_events}")
            lines.append(f"  Total Alerts:  {report.total_alerts}")
            if report.input_files:
                lines.append(f"  Input Files:   {', '.join(report.input_files)}")
            lines.append(f"")

            # Severity breakdown
            lines.append("-" * 70)
            lines.append("  SEVERITY BREAKDOWN")
            lines.append("-" * 70)
            severity_counts = report.summary.get("severity_breakdown", {})
            total = sum(severity_counts.values()) or 1
            for sev in SEVERITY_ORDER:
                count = severity_counts.get(sev, 0)
                bar_len = int((count / total) * 30) if total else 0
                bar = "#" * bar_len
                lines.append(f"  {sev:<10} {count:>4}  {bar}")
            lines.append(f"")

            # Top source IPs
            top_ips = report.summary.get("top_source_ips", [])
            if top_ips:
                lines.append("-" * 70)
                lines.append("  TOP SOURCE IPs")
                lines.append("-" * 70)
                for entry in top_ips[:5]:
                    lines.append(f"  {entry['ip']:<20} {entry['alert_count']} alerts")
                lines.append(f"")

            # Alert details
            lines.append("-" * 70)
            lines.append("  ALERT DETAILS")
            lines.append("-" * 70)
            if report.alerts:
                for i, alert in enumerate(report.alerts, 1):
                    lines.append(f"")
                    lines.append(f"  [{i}] {alert.rule_id}: {alert.title}")
                    lines.append(f"      Severity:    {alert.severity}")
                    if alert.source_ip:
                        lines.append(f"      Source IP:   {alert.source_ip}")
                    lines.append(f"      Count:       {alert.count}")
                    if alert.description:
                        lines.append(f"      Description: {alert.description[:100]}")
                    if alert.recommendation:
                        lines.append(f"      Action:      {alert.recommendation[:100]}")
            else:
                lines.append(f"  No alerts generated.")

            lines.append(f"")
            lines.append("=" * 70)
            lines.append(f"  Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append("=" * 70)

            content = "\n".join(lines)

            output_path = os.path.join(self.output_dir, f"{report_name}.txt")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Only print to stdout if explicitly requested
            if print_output:
                print(content)

            return output_path

        except Exception as e:
            print(f"Warning: Terminal report generation failed: {e}")
            return None

    def _generate_charts(
        self,
        report: Report,
        chart_dir: str,
    ) -> dict[str, str]:
        """
        Generate matplotlib charts for the report.

        Args:
            report: The Report object with summary data.
            chart_dir: Directory to save chart images.

        Returns:
            Dict mapping chart names to file paths.
        """
        os.makedirs(chart_dir, exist_ok=True)
        charts: dict[str, str] = {}

        severity_counts = report.summary.get("severity_breakdown", {})
        rule_breakdown = report.summary.get("rule_breakdown", {})

        # Style configuration with fallback for different matplotlib versions
        try:
            plt.style.use("seaborn-v0_8-darkgrid")
        except OSError:
            try:
                plt.style.use("seaborn-darkgrid")
            except OSError:
                plt.style.use("default")

        # 1. Severity Distribution Pie Chart
        if severity_counts:
            fig, ax = plt.subplots(figsize=(8, 6))
            labels = []
            sizes = []
            colors = []
            explode = []

            for sev in SEVERITY_ORDER:
                if sev in severity_counts:
                    labels.append(sev)
                    sizes.append(severity_counts[sev])
                    colors.append(SEVERITY_COLORS.get(sev, "#6c757d"))
                    explode.append(0.05 if sev == "Critical" else 0.02)

            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct="%1.1f%%",
                startangle=140,
                explode=explode,
                shadow=True,
                textprops={"fontsize": 12, "fontweight": "bold"},
            )
            for autotext in autotexts:
                autotext.set_color("white")
                autotext.set_fontweight("bold")

            ax.set_title("Alert Severity Distribution", fontsize=14, fontweight="bold", pad=20)
            plt.tight_layout()

            chart_path = os.path.join(chart_dir, "severity_pie.png")
            fig.savefig(chart_path, dpi=150, bbox_inches="tight")
            plt.close(fig)
            charts["severity_pie"] = chart_path

        # 2. Rule Breakdown Bar Chart
        if rule_breakdown:
            fig, ax = plt.subplots(figsize=(10, 6))

            rules = sorted(rule_breakdown.items(), key=lambda x: x[1], reverse=True)
            rule_labels = [r[0] for r in rules]
            rule_counts = [r[1] for r in rules]

            # Color bars by severity if possible
            rule_to_severity = {}
            for alert in report.alerts:
                if alert.rule_id not in rule_to_severity:
                    rule_to_severity[alert.rule_id] = alert.severity

            bar_colors = []
            for rule_id in rule_labels:
                sev = rule_to_severity.get(rule_id, "Low")
                bar_colors.append(SEVERITY_COLORS.get(sev, "#6c757d"))

            bars = ax.barh(rule_labels, rule_counts, color=bar_colors, edgecolor="white", height=0.6)

            # Add count labels on bars
            for bar, count in zip(bars, rule_counts):
                ax.text(
                    bar.get_width() + 0.3,
                    bar.get_y() + bar.get_height() / 2,
                    str(count),
                    va="center",
                    fontsize=11,
                    fontweight="bold",
                )

            ax.set_xlabel("Alert Count", fontsize=12)
            ax.set_title("Alerts by Detection Rule", fontsize=14, fontweight="bold", pad=15)
            ax.set_xlim(0, max(rule_counts) * 1.2 + 1)
            ax.invert_yaxis()
            plt.tight_layout()

            chart_path = os.path.join(chart_dir, "rule_breakdown.png")
            fig.savefig(chart_path, dpi=150, bbox_inches="tight")
            plt.close(fig)
            charts["rule_breakdown"] = chart_path

        # 3. Alerts Timeline Chart (if enough timestamp data)
        if len(report.alerts) >= 2:
            fig, ax = plt.subplots(figsize=(10, 5))

            timestamps = [a.timestamp for a in report.alerts]
            severities = [a.severity for a in report.alerts]
            y_positions = range(len(report.alerts))

            point_colors = [SEVERITY_COLORS.get(s, "#6c757d") for s in severities]
            sizes = [a.count * 10 + 20 for a in report.alerts]  # Scale by count

            ax.scatter(timestamps, y_positions, c=point_colors, s=sizes, alpha=0.7, edgecolors="white", linewidth=0.5)

            ax.set_yticks(y_positions)
            ax.set_yticklabels([f"{a.rule_id}" for a in report.alerts], fontsize=9)
            ax.set_xlabel("Time", fontsize=12)
            ax.set_title("Alerts Timeline", fontsize=14, fontweight="bold", pad=15)
            ax.grid(True, alpha=0.3)

            # Add severity legend
            from matplotlib.patches import Patch
            legend_elements = [
                Patch(facecolor=SEVERITY_COLORS[s], label=s)
                for s in SEVERITY_ORDER
                if s in severities
            ]
            ax.legend(handles=legend_elements, loc="upper right", fontsize=10)

            plt.tight_layout()

            chart_path = os.path.join(chart_dir, "alerts_timeline.png")
            fig.savefig(chart_path, dpi=150, bbox_inches="tight")
            plt.close(fig)
            charts["alerts_timeline"] = chart_path

        return charts

    def _report_to_dict(self, report: Report) -> dict[str, Any]:
        """Convert a Report object to a JSON-serializable dict."""
        alerts_data = []
        for alert in report.alerts:
            alert_dict = {
                "rule_id": alert.rule_id,
                "title": alert.title,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "count": alert.count,
                "timestamp": alert.timestamp.isoformat(),
                "mitre_technique": alert.mitre_technique,
                "description": alert.description,
                "recommendation": alert.recommendation,
                "events": [
                    {
                        "timestamp": e.timestamp.isoformat(),
                        "source": e.source,
                        "host": e.host,
                        "parsed": e.parsed,
                    }
                    for e in alert.events
                ],
            }
            alerts_data.append(alert_dict)

        return {
            "report_metadata": {
                "tool": "LogSentinel",
                "version": "1.0.0",
                "scan_time": report.scan_time.isoformat(),
                "generated_at": datetime.now().isoformat(),
            },
            "summary": {
                "total_events": report.total_events,
                "total_alerts": report.total_alerts,
                "input_files": report.input_files,
                "severity_breakdown": report.summary.get("severity_breakdown", {}),
                "rule_breakdown": report.summary.get("rule_breakdown", {}),
                "top_source_ips": report.summary.get("top_source_ips", []),
            },
            "alerts": alerts_data,
        }
