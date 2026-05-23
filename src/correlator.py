"""
LogSentinel - Alert Correlator

Correlates and enriches alerts after detection:
  - Groups related alerts from the same source IP
  - Recalculates severity based on alert frequency and criticality
  - Deduplicates overlapping alerts within configurable time window
  - Generates summary statistics
"""

from collections import defaultdict
from datetime import datetime
from typing import Any

from .models import Alert, Report


class AlertCorrelator:
    """Correlates, deduplicates, and enriches alerts for final reporting."""

    def __init__(self, merge_window_seconds: int = 300):
        """
        Initialize the correlator.

        Args:
            merge_window_seconds: Time window in seconds for merging related alerts.
        """
        self.merge_window = merge_window_seconds

    def process(self, alerts: list[Alert]) -> list[Alert]:
        """
        Process raw alerts through the correlation pipeline.

        Steps:
        1. Deduplicate overlapping alerts (grouped by rule, IP, and time window)
        2. Enrich with additional context
        3. Recalculate severity

        Args:
            alerts: Raw list of Alert objects from the detection engine.

        Returns:
            Processed list of Alert objects.
        """
        if not alerts:
            return []

        # Deduplicate and merge
        merged = self._deduplicate(alerts)

        # Recalculate severity
        for alert in merged:
            alert.severity = self._recalculate_severity(alert)

        return merged

    def _deduplicate(self, alerts: list[Alert]) -> list[Alert]:
        """
        Merge alerts that refer to the same incident from the same source.
        Threshold-based alerts from the same IP with the same rule are merged
        if they occur within the configured merge_window_seconds.
        """
        # Group by (rule_id, source_ip)
        groups: dict[tuple[str, str], list[Alert]] = defaultdict(list)
        for alert in alerts:
            key = (alert.rule_id, alert.source_ip)
            groups[key].append(alert)

        merged_alerts: list[Alert] = []

        for key, group in groups.items():
            if len(group) == 1:
                merged_alerts.append(group[0])
            else:
                # Further split by time window so distant alerts aren't merged
                group.sort(key=lambda a: a.timestamp)
                time_windows: list[list[Alert]] = []

                for alert in group:
                    added = False
                    for window in time_windows:
                        if abs((alert.timestamp - window[0].timestamp).total_seconds()) <= self.merge_window:
                            window.append(alert)
                            added = True
                            break
                    if not added:
                        time_windows.append([alert])

                # Merge alerts within each time window
                for window in time_windows:
                    if len(window) == 1:
                        merged_alerts.append(window[0])
                    else:
                        all_events: list = []
                        total_count = 0
                        timestamps: list[datetime] = []

                        for a in window:
                            all_events.extend(a.events)
                            total_count += a.count
                            timestamps.append(a.timestamp)

                        merged = Alert(
                            rule_id=window[0].rule_id,
                            title=window[0].title,
                            severity=window[0].severity,
                            source_ip=window[0].source_ip,
                            events=all_events,
                            count=total_count,
                            timestamp=max(timestamps),
                            mitre_technique=window[0].mitre_technique,
                            recommendation=window[0].recommendation,
                            description=window[0].description,
                        )
                        merged_alerts.append(merged)

        return merged_alerts

    def _recalculate_severity(self, alert: Alert) -> str:
        """
        Recalculate severity based on event count and original severity.

        Severity escalation:
        - If count > 50: escalate by 1 level
        - If count > 100: escalate by 2 levels
        - Critical stays Critical regardless
        - If target is malware/web attack with successful response, escalate
        """
        severity_levels = ["Low", "Medium", "High", "Critical"]

        base_severity = alert.severity
        if base_severity == "Critical":
            return "Critical"

        base_idx = severity_levels.index(base_severity) if base_severity in severity_levels else 0

        # Escalate based on volume
        escalation = 0
        if alert.count > 100:
            escalation = 2
        elif alert.count > 50:
            escalation = 1

        # Check for successful exploitation in web-related alerts
        if any(
            event.source == "access.log" and event.parsed.get("status", 0) in (200, 201, 302)
            for event in alert.events
        ):
            # Successful response to an attack attempt
            if alert.rule_id in ("DET-003", "DET-004"):
                escalation = max(escalation, 2)  # At minimum, escalate to Critical

        new_idx = min(base_idx + escalation, len(severity_levels) - 1)
        return severity_levels[new_idx]

    def generate_report(
        self,
        alerts: list[Alert],
        total_events: int = 0,
        input_files: list[str] | None = None,
    ) -> Report:
        """
        Generate a comprehensive Report from processed alerts.

        Args:
            alerts: Processed list of Alert objects.
            total_events: Total number of log events analyzed.
            input_files: List of input log file paths.

        Returns:
            A Report object with summary statistics.
        """
        if input_files is None:
            input_files = []

        # Build summary statistics
        severity_counts: dict[str, int] = defaultdict(int)
        rule_counts: dict[str, int] = defaultdict(int)
        top_ips: dict[str, int] = defaultdict(int)

        for alert in alerts:
            severity_counts[alert.severity] += 1
            rule_counts[alert.rule_id] += 1
            if alert.source_ip:
                top_ips[alert.source_ip] += 1

        # Sort top IPs by alert count
        sorted_ips = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]

        summary: dict[str, Any] = {
            "total_alerts": len(alerts),
            "severity_breakdown": dict(severity_counts),
            "rule_breakdown": dict(rule_counts),
            "top_source_ips": [
                {"ip": ip, "alert_count": count}
                for ip, count in sorted_ips
            ],
        }

        return Report(
            scan_time=datetime.now(),
            total_events=total_events,
            total_alerts=len(alerts),
            alerts=alerts,
            summary=summary,
            input_files=input_files,
        )
