# Usage Guide

## Command-Line Interface

```
usage: logsentinel [-h] [--sample] [--rules RULES] [--output-dir OUTPUT_DIR]
                   [--source {auth.log,access.log,syslog}]
                   [--format {html,json,terminal,all}] [--verbose] [--version]
                   [log_files ...]
```

## Arguments

### Positional Arguments

| Argument | Description |
|----------|-------------|
| `log_files` | One or more paths to log files to analyze. Supports glob patterns. |

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--sample` | Analyze bundled sample log files | `False` |
| `--rules, -r` | Path to detection rules YAML config | `config/rules.yaml` |
| `--output-dir, -o` | Output directory for reports | `./reports` |
| `--source, -s` | Override log source auto-detection | Auto-detect |
| `--format, -f` | Output format: `html`, `json`, `terminal`, `all` | `all` |
| `--verbose, -v` | Show detailed progress during analysis | `False` |
| `--version` | Show version and exit | — |
| `-h, --help` | Show help message and exit | — |

## Usage Examples

### 1. Analyze Sample Logs

Quickest way to see LogSentinel in action:

```bash
logsentinel --sample
```

### 2. Analyze Specific Log Files

```bash
# Single log file
logsentinel sample_logs/auth.log

# Multiple log files
logsentinel sample_logs/auth.log sample_logs/access.log

# Using glob patterns
logsentinel sample_logs/
```

### 3. Generate Only HTML Reports

```bash
logsentinel sample_logs/auth.log --format html
```

### 4. With Verbose Output

Shows each pipeline stage with event counts:

```bash
logsentinel sample_logs/auth.log --verbose
```

### 5. Custom Output Directory

```bash
logsentinel sample_logs/auth.log --output-dir ./security_reports
```

### 6. Custom Rules Configuration

```bash
logsentinel sample_logs/auth.log --rules ./custom_rules.yaml
```

### 7. Override Source Detection

If auto-detection fails or you want to force a source:

```bash
logsentinel custom_log.txt --source auth.log
```

### 8. Real-World Usage

```bash
# Analyze system auth logs
sudo logsentinel /var/log/auth.log --verbose --format html

# Analyze web server logs
logsentinel /var/log/apache2/access.log --format json

# Analyze everything with detailed output
logsentinel /var/log/auth.log /var/log/apache2/access.log --verbose
```

## Output Formats

### HTML Report

Professional dark-themed HTML report with:
- Severity summary cards
- Matplotlib charts (pie, bar, timeline)
- Alert table with MITRE ATT&CK mappings
- Responsive design

### JSON Report

Structured JSON for SIEM integration:

```json
{
  "report_metadata": { ... },
  "summary": {
    "total_alerts": 7,
    "total_events": 46,
    "severity_breakdown": { ... },
    "rule_breakdown": { ... }
  },
  "alerts": [
    {
      "rule_id": "DET-001",
      "severity": "High",
      "source_ip": "192.168.1.100",
      "events": [ ... ]
    }
  ]
}
```

### Terminal Report

Colorized console output with severity bars and alert details.

## Pipeline Architecture

The analysis runs in 4 stages:

1. **Parse** — Read and parse raw log files into structured LogEvents
2. **Detect** — Apply detection rules to generate raw alerts
3. **Correlate** — Deduplicate, merge, and recalculate severity
4. **Report** — Generate HTML, JSON, and terminal outputs
