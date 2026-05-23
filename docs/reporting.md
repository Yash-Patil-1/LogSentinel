# Report Formats

LogSentinel generates three report formats for every analysis run.

## HTML Report

The HTML report is the primary deliverable, designed for handoff to L2 analysts. It features a professional dark theme inspired by GitHub UI.

### Sections

#### 1. Header
- Report title and metadata (generation timestamp, input files)
- Shield badges with alert counts

#### 2. Summary Cards
- **Total Alerts**: Number of correlated alerts
- **Total Events**: Number of parsed log events
- **Critical Alerts**: Count of Critical severity alerts
- **High Alerts**: Count of High severity alerts

#### 3. Charts Panel

Three matplotlib charts are embedded:

| Chart | Type | Description |
|-------|------|-------------|
| Severity Distribution | Pie | Proportion of alerts by severity level |
| Rule Breakdown | Bar | Alert count per detection rule |
| Alerts Timeline | Scatter | Alert chronology during the analysis period |

Charts are stored in a `charts/` subdirectory relative to the report.

#### 4. Alert Table

Each alert row includes:
- **Severity Badge**: Color-coded (Critical=red, High=orange, Medium=yellow, Low=green)
- **Rule ID**: Detection rule identifier
- **Attack Type**: Human-readable attack name
- **Source IP**: Attacker IP address
- **Events**: Count of matching events
- **Description**: Detailed alert description
- **MITRE ID**: ATT&CK technique reference
- **Recommendation**: Response actions

### Styling

- Dark background (`#0d1117`)
- Card-based layout with subtle borders
- Responsive grid (adapts to mobile/desktop)
- Monospace font for technical details
- Hover effects on table rows

## JSON Report

Structured JSON output for programmatic processing and SIEM integration.

### Schema

```json
{
  "report_metadata": {
    "report_name": "logsentinel_report_20260523_105643",
    "generated_at": "2026-05-23T10:56:43",
    "logsentinel_version": "1.0.0"
  },
  "summary": {
    "total_alerts": 7,
    "total_events": 46,
    "input_files": ["access.log", "auth.log", "syslog"],
    "severity_breakdown": {
      "Critical": 2,
      "High": 3,
      "Medium": 2,
      "Low": 0
    },
    "rule_breakdown": {
      "DET-001": 2,
      "DET-003": 1,
      "DET-005": 1
    }
  },
  "alerts": [
    {
      "rule_id": "DET-001",
      "title": "SSH Brute Force Attack",
      "severity": "High",
      "source_ip": "192.168.1.100",
      "timestamp": "2026-05-23T08:15:32",
      "count": 10,
      "description": "Multiple failed SSH login attempts...",
      "mitre_technique": "T1110",
      "events": [
        {
          "timestamp": "2026-05-23T08:15:32",
          "source": "auth.log",
          "parsed": {
            "event_type": "failed_login",
            "user": "root",
            "ip": "192.168.1.100"
          }
        }
      ]
    }
  ]
}
```

### Usage

- Ingest into SIEM platforms (Splunk, ELK, Sentinel)
- Programmatic analysis with Python scripts
- Automated report archiving and comparison
- Integration with ticketing systems

## Terminal Report

Colorized console output for real-time review.

### Features

- ASCII header banner with version
- Alert count summary by severity
- Severity breakdown bar chart (text-based)
- Per-alert details with severity color coding
- File-based output for logging

### Color Scheme

| Severity | Color | ANSI Code |
|----------|-------|-----------|
| Critical | Red | `\033[91m` |
| High | Orange/Yellow | `\033[93m` |
| Medium | Blue | `\033[94m` |
| Low | Green | `\033[92m` |

## Report Storage

Reports are saved to the specified output directory (default: `./reports/`).

```
reports/
├── logsentinel_report_20260523_105643.html
├── logsentinel_report_20260523_105643.json
├── logsentinel_report_20260523_105643.txt
└── charts/
    ├── severity_pie.png
    ├── rule_breakdown.png
    └── alerts_timeline.png
```

Each run creates a unique timestamped report set. The charts directory is embedded within the HTML output but stored alongside it for portability.
