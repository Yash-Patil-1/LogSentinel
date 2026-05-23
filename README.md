<div align="center">
  <h1>🔍 LogSentinel</h1>
  <p><strong>Log Analysis & Threat Detection Engine</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python" alt="Python version">
    <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
    <img src="https://img.shields.io/badge/Status-Beta-yellow?style=flat-square" alt="Status">
    <img src="https://img.shields.io/badge/coverage-94%25-brightgreen?style=flat-square" alt="Coverage">
  </p>
  <p><em>SOC-grade CLI tool for log parsing, threat detection, alert correlation, and professional security reporting.</em></p>
</div>

---

## 📋 Overview

LogSentinel simulates a real-world **SOC L1 triage workflow**. It ingests raw log files (SSH auth logs, Apache access logs, syslog), applies regex-based detection rules, correlates events across multiple sources, and generates structured security alerts with severity scoring. The tool outputs comprehensive HTML reports with visualizations and JSON for SIEM integration.

**Why this project?** Log analysis is the #1 skill for entry-level SOC analysts. This project demonstrates practical ability to parse logs, write detection logic, triage alerts, and produce professional reports.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Multi-format Parsing** | Parse SSH auth logs, Apache access logs, and syslog kernel messages |
| **7 Detection Rules** | SSH brute force, port scans, SQLi, XSS, privilege escalation, directory traversal, user enumeration |
| **Alert Correlation** | Deduplication, severity recalculation, time-window merging |
| **HTML Reports** | Dark-themed professional reports with matplotlib charts (pie, bar, timeline) |
| **JSON Export** | Structured output for SIEM ingestion and programmatic processing |
| **Terminal Output** | Colorized real-time console reporting |
| **MITRE ATT&CK** | Each alert mapped to MITRE technique IDs |
| **Configurable Rules** | YAML-based rule configuration |
| **Bundled Sample Logs** | Realistic attack scenarios included for testing |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/YashPatil/LogSentinel.git
cd LogSentinel

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install LogSentinel
pip install -e .
```

### Basic Usage

```bash
# Analyze bundled sample logs
logsentinel --sample

# Analyze specific log files
logsentinel sample_logs/auth.log

# Generate HTML report with verbose output
logsentinel sample_logs --format html --verbose

# Specify custom output directory
logsentinel sample_logs/auth.log --output-dir ./reports

# Show help
logsentinel --help
```

### Example Output

```
$ logsentinel --sample --verbose
[+] Using sample logs: access.log, auth.log, syslog
[+] LogSentinel v1.0.0 - Security Analysis Pipeline

[*] Stage 1/4: Parsing log files...
  [ ] Parsed   13 events from access.log
  [ ] Parsed   27 events from auth.log
  [ ] Parsed    6 events from syslog
  [+] Total: 46 events parsed

[*] Stage 2/4: Running detection engine...
  [+] 13 raw alerts generated

[*] Stage 3/4: Correlating alerts...
  [+] 7 alerts after correlation

[*] Stage 4/4: Generating reports...
  [+]     HTML: reports/logsentinel_report_20260523_105643.html
  [+]     JSON: reports/logsentinel_report_20260523_105643.json
  [+] TERMINAL: reports/logsentinel_report_20260523_105643.txt

[+] Analysis complete.
```

---

## 🔍 Detection Rules

| Rule ID | Attack Type | Log Source | Threshold | Severity | MITRE |
|---------|-------------|-----------|-----------|----------|-------|
| DET-001 | SSH Brute Force | auth.log | 5 failures/60s | High | T1110 |
| DET-002 | Port Scan | auth.log/syslog | 10 ports/60s | Medium | T1046 |
| DET-003 | SQL Injection | access.log | 1+ occurrence | High | T1190 |
| DET-004 | XSS Attack | access.log | 1+ occurrence | Medium | T1059.007 |
| DET-005 | Privilege Escalation | auth.log | failure→success/300s | Critical | T1068 |
| DET-006 | Directory Traversal | access.log | 1+ occurrence | Medium | T1190 |
| DET-007 | User Enumeration | auth.log | 3+ users/60s | Medium | T1589.001 |

Rules are fully configurable via `config/rules.yaml`. Thresholds, time windows, and severity can be adjusted without code changes.

---

## 📁 Project Structure

```
LogSentinel/
├── pyproject.toml          # Package configuration
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── PRD.md                  # Product requirements document
├──
├── config/
│   └── rules.yaml          # 7 detection rules (YAML)
├──
├── src/
│   ├── __init__.py         # Package init (version: 1.0.0)
│   ├── models.py           # LogEvent, Alert, Report dataclasses
│   ├── parser.py           # Log parsers (auth, access, syslog)
│   ├── detector.py         # DetectionEngine (threshold/pattern/correlation)
│   ├── correlator.py       # AlertCorrelator (dedup, severity, summary)
│   ├── reporter.py         # Reporter (HTML, JSON, Terminal output)
│   ├── main.py             # CLI entry point
│   └── templates/
│       └── report.html     # Jinja2 HTML template
├──
├── sample_logs/
│   ├── auth.log            # SSH brute force + privilege escalation
│   ├── access.log          # SQLi, XSS, directory traversal
│   └── syslog              # Kernel port scan messages
├──
├── tests/
│   ├── test_parser.py      # 22 tests — log parsing
│   ├── test_detector.py    # 11 tests — detection rules
│   ├── test_correlator.py  # 11 tests — alert correlation
│   ├── test_reporter.py    # 9 tests — report generation
│   └── test_main.py        # 9 tests — CLI integration
│
├── reports/                # Generated report output
└── docs/                   # Documentation
```

---

## 🧪 Running Tests

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run all tests
python3 -m pytest tests/ -v

# Run with coverage
python3 -m pytest tests/ --cov=src --cov-report=term
```

**Current test results: 62/62 passing, 94% coverage**

---

## 🛠️ CLI Reference

```
usage: logsentinel [-h] [--sample] [--rules RULES] [--output-dir OUTPUT_DIR]
                   [--source {auth.log,access.log,syslog}]
                   [--format {html,json,terminal,all}] [--verbose] [--version]
                   [log_files ...]

Positional Arguments:
  log_files              Path(s) to log file(s) to analyze

Options:
  --sample               Analyze bundled sample log files
  --rules, -r RULES      Path to rules YAML config
  --output-dir, -o DIR   Output directory (default: ./reports)
  --source, -s           Override log source auto-detection
  --format, -f           Output format: html, json, terminal, all
  --verbose, -v          Detailed progress output
  --version              Show version and exit
```

---

## 📊 Sample Report Preview

The HTML report features:
- **Dark GitHub-inspired theme** (#0d1117 background)
- **Summary cards** with total alerts, events, critical count
- **Severity pie chart** — alert distribution
- **Rule breakdown bar chart** — alerts by detection rule
- **Alerts timeline scatter plot** — attack chronology
- **Alert table** with severity badges, MITRE IDs, descriptions, recommendations
- **Responsive design** for desktop and mobile

---

## 📝 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Yash Patil** — Cybersecurity Analyst | SOC Operations & Incident Response
- 📧 yashpatil7714@gmail.com
- 🔗 [LinkedIn]([https://www.linkedin.com/in/yash-patil-997357330])
- 🐙 [GitHub](https://github.com/Yash-Patil-1)

---

<div align="center">
  <sub>Built with Python, matplotlib, Jinja2, and a passion for security.</sub>
</div>
