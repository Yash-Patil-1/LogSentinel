# 📋 PRD: LogSentinel — Log Analysis & Threat Detection Engine

> **Project:** LogSentinel (Beginner Level)
> **Author:** Yash Patil
> **Role:** SOC Analyst | Cybersecurity Analyst
> **Status:** ✅ Planned
> **Last Updated:** May 21, 2026

---

## 1. Executive Summary

LogSentinel is a Python-based CLI tool that simulates real-world SOC L1 triage workflow. It ingests raw log files (SSH auth logs, Apache access logs, syslog), applies regex-based detection rules, correlates events across multiple sources, and generates structured security alerts with severity scoring. The tool outputs comprehensive HTML/JSON reports suitable for handoff to L2 analysts.

**Why this project?** Log analysis is the #1 skill for entry-level SOC analysts. This project demonstrates practical ability to parse logs, write detection logic, triage alerts, and produce professional reports — exactly what employers look for.

---

## 2. Goals & Learning Objectives

| Goal | Description |
|------|-------------|
| **Log Parsing** | Parse SSH auth logs, Apache access logs, and syslog into structured events |
| **Detection Rules** | Implement regex-based rules for brute force, port scans, web attacks, privilege escalation |
| **Alert Triage** | Assign severity levels (Critical/High/Medium/Low) based on frequency & pattern matching |
| **Reporting** | Generate HTML reports with visualizations (charts, timelines) and JSON for SIEM ingestion |
| **CLI Usability** | Build a clean, professional CLI with flags for input, output, and configuration |

---

## 3. Features

### 3.1 Core Features (Must-Have)

| Feature | Priority | Description |
|---------|----------|-------------|
| Multi-format log parsing | P0 | Parse SSH auth.log, Apache access.log, and syslog |
| Detection rules engine | P0 | Regex-based rules for 5+ attack types |
| Severity classification | P0 | Critical/High/Medium/Low based on thresholds |
| HTML report generation | P0 | Professional report with charts and timeline |
| JSON export | P0 | Structured JSON output for SIEM integration |
| CLI argument parsing | P0 | `-i` input, `-o` output, `-c` config, `-f` format |

### 3.2 Detection Rules

| Rule ID | Attack Type | Log Source | Description |
|---------|-------------|-----------|-------------|
| DET-001 | SSH Brute Force | auth.log | >5 failed logins from same IP in 60s |
| DET-002 | Port Scan | auth.log/syslog | Connection attempts to multiple ports from single IP |
| DET-003 | SQL Injection | access.log | SQL keywords in GET/POST parameters |
| DET-004 | XSS Attack | access.log | Script tags or event handlers in parameters |
| DET-005 | Privilege Escalation | auth.log | Failed sudo attempts followed by success |
| DET-006 | Directory Traversal | access.log | "../" patterns in URL paths |
| DET-007 | User Enumeration | auth.log | Invalid user repeated from same IP |

### 3.3 Severity Scoring

| Severity | Criteria |
|----------|----------|
| **Critical** | Confirmed exploitation attempt (e.g., SQLi with successful response) |
| **High** | Sustained attack pattern (e.g., 20+ brute force attempts) |
| **Medium** | Suspicious activity below threshold (e.g., 3-5 failed logins) |
| **Low** | Informational / anomalous but not clearly malicious |

### 3.4 Additional Features (Nice-to-Have)

- Sample log generators for testing
- MITRE ATT&CK technique mapping for each alert
- Configurable rules via YAML config file
- Colorized terminal output for real-time monitoring feel
- CSV export format

---

## 4. Technical Architecture

### 4.1 High-Level Architecture

```
┌─────────────┐    ┌───────────────┐    ┌──────────────┐
│  Log Files   │───▶│  Parser Layer │───▶│  Detection   │
│ (auth.log,   │    │  (Normalize   │    │  Engine      │
│  access.log, │    │   to Events)  │    │  (Rules)     │
│  syslog)     │    │               │    │              │
└─────────────┘    └───────────────┘    └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │  Alert       │
                                        │  Correlator  │
                                        │  & Scorer    │
                                        └──────┬───────┘
                                               │
                               ┌───────────────┼───────────────┐
                               │               │               │
                        ┌──────▼─────┐  ┌──────▼─────┐  ┌─────▼──────┐
                        │  HTML      │  │  JSON      │  │  Terminal  │
                        │  Report    │  │  Export    │  │  Output    │
                        └────────────┘  └────────────┘  └────────────┘
```

### 4.2 Module Breakdown

| Module | File | Responsibility |
|--------|------|---------------|
| **CLI Entry** | `main.py` | Argument parsing, orchestration |
| **Log Parser** | `parser.py` | Parse different log formats into unified Event objects |
| **Detection Engine** | `detector.py` | Apply rules against parsed events |
| **Alert Correlator** | `correlator.py` | Group related alerts, assign severity |
| **Report Generator** | `reporter.py` | Generate HTML/JSON/CSV output |
| **Config** | `config.py` | Load rules and thresholds from config |
| **Models** | `models.py` | Data classes for LogEvent, Alert, Report |

### 4.3 Data Models

```python
@dataclass
class LogEvent:
    timestamp: datetime
    source: str          # 'auth.log', 'access.log', 'syslog'
    raw: str             # Original log line
    parsed: dict         # Extracted fields (ip, user, method, path, etc.)
    host: str

@dataclass
class Alert:
    rule_id: str         # e.g., 'DET-001'
    title: str           # e.g., 'SSH Brute Force Detected'
    severity: str        # Critical/High/Medium/Low
    source_ip: str
    events: list[LogEvent]
    count: int
    timestamp: datetime
    mitre_technique: str
    recommendation: str

@dataclass
class Report:
    scan_time: datetime
    total_events: int
    total_alerts: int
    alerts: list[Alert]
    summary: dict        # Severity breakdown, top IPs, top rules
```

---

## 5. Directory Structure

```
SOC/LogSentinel/
├── PRD.md                    # This document
├── README.md                 # GitHub README
├── requirements.txt          # Python dependencies
├── config/
│   └── rules.yaml            # Detection rules configuration
├── src/
│   ├── main.py               # CLI entry point
│   ├── parser.py             # Log parsers
│   ├── detector.py           # Detection engine
│   ├── correlator.py         # Alert correlation & scoring
│   ├── reporter.py           # Report generation (HTML, JSON)
│   └── models.py             # Data models
├── sample_logs/
│   ├── auth.log              # Sample SSH auth log
│   ├── access.log            # Sample Apache access log
│   └── syslog                # Sample syslog
├── tests/
│   ├── test_parser.py
│   ├── test_detector.py
│   └── test_correlator.py
└── docs/
    ├── usage.md              # Usage guide
    ├── detection_rules.md    # Rule documentation
    └── examples.md           # Example outputs
```

---

## 6. Implementation Plan

### Phase 1: Foundation
- [ ] Create data models (LogEvent, Alert, Report)
- [ ] Implement log parsers (SSH, Apache, syslog)
- [ ] Write unit tests for parsers

### Phase 2: Detection Engine
- [ ] Implement detection rules (DET-001 to DET-007)
- [ ] Build alert correlator & severity scorer
- [ ] Write unit tests for detection logic

### Phase 3: Reporting
- [ ] Build JSON export
- [ ] Build HTML report with charts (matplotlib/plotly)
- [ ] Build terminal output with colorization

### Phase 4: Sample Data & Polish
- [ ] Create sample log files with realistic attack patterns
- [ ] Add CLI argument parsing
- [ ] Add configurable rules via YAML

### Phase 5: Documentation
- [ ] Write README.md for GitHub
- [ ] Write usage guide (docs/usage.md)
- [ ] Write detection rules guide (docs/detection_rules.md)
- [ ] Write examples with screenshots (docs/examples.md)

---

## 7. Dependencies

| Library | Purpose |
|---------|---------|
| `click` or `argparse` | CLI argument parsing (stdlib) |
| `jinja2` | HTML template rendering |
| `matplotlib` | Charts for HTML report |
| `pyyaml` | Config file parsing |
| None | Core logic uses only stdlib where possible |

---

## 8. GitHub Documentation Plan

The repository will include:
- **README.md** — Project overview, features, architecture diagram, installation, quick start, screenshots
- **docs/usage.md** — Detailed CLI flags, configuration, examples
- **docs/detection_rules.md** — Each rule explained with examples
- **docs/examples.md** — Full walkthrough with sample outputs and screenshots
- **LICENSE** — MIT License
- **requirements.txt** — Dependencies

---

## 9. Success Criteria

- [ ] Tool successfully parses all 3 log formats
- [ ] All 7 detection rules fire correctly on malicious patterns
- [ ] False positive rate < 10% on clean logs
- [ ] HTML report renders correctly with charts
- [ ] JSON output is valid and structured
- [ ] CLI accepts all specified flags
- [ ] All unit tests pass (>80% coverage)

---

## 10. MITRE ATT&CK Mapping

| Detection | MITRE Technique ID | Technique Name |
|-----------|-------------------|----------------|
| SSH Brute Force | T1110 | Brute Force |
| Port Scan | T1046 | Network Service Scanning |
| SQL Injection | T1190 | Exploit Public-Facing Application |
| XSS | T1190 | Exploit Public-Facing Application |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Directory Traversal | T1190 | Exploit Public-Facing Application |
| User Enumeration | T1589 | Gather Victim Identity Information |

---

*This PRD is a living document and will be updated as the project evolves.*
