# Architecture Overview

## High-Level Architecture

```
┌─────────────┐    ┌───────────────┐    ┌──────────────┐    ┌──────────────┐
│   Parser    │───▶│   Detector    │───▶│  Correlator  │───▶│   Reporter   │
│  (Phase 1)  │    │  (Phase 2)    │    │  (Phase 2)   │    │  (Phase 3)   │
└─────────────┘    └───────────────┘    └──────────────┘    └──────────────┘
       │                   │                    │                   │
       ▼                   ▼                    ▼                   ▼
  Raw logs ─────▶  LogEvents ─────▶   Alerts  ─────▶  Processed ────▶ HTML/JSON
  (.log files)     (structured)      (raw)         Alerts + Report   Terminal
```

## Pipeline Stages

### Stage 1: Parse

**Input:** Raw log files (auth.log, access.log, syslog)
**Output:** List of `LogEvent` objects

- Auto-detects log source if not specified
- Three specialized parsers: SSH auth, Apache access, syslog kernel
- Each parser uses regex to extract structured fields from raw log lines
- Returns `LogEvent` dataclasses with `timestamp`, `source`, `raw`, `parsed` dict, `host`

### Stage 2: Detect

**Input:** List of `LogEvent` objects
**Output:** List of `Alert` objects (raw, uncorrelated)

- Loads detection rules from `config/rules.yaml`
- Three check types:
  - **Threshold rules**: Count events matching criteria within a sliding time window
  - **Pattern rules**: Apply regex patterns against parsed event fields
  - **Correlation rules**: Sequence-based detection (e.g., failure → success)
- Generates alerts with MITRE ATT&CK technique mappings
- Each alert captures source events for evidence preservation

### Stage 3: Correlate

**Input:** List of `Alert` objects
**Output:** Processed `Alert` list + `Report` object

- **Deduplication**: Groups alerts by `(rule_id, source_ip)` within configurable time windows
- **Severity Escalation**: Escalates severity based on alert frequency (50+ → High, 100+ → Critical) and successful exploit responses
- **Report Generation**: Computes summary statistics, severity breakdown, rule breakdown, timeline

### Stage 4: Report

**Input:** `Report` object
**Output:** HTML, JSON, and terminal report files

- Three output generators:
  - **HTML**: Jinja2 template with dark GitHub-inspired theme, matplotlib charts, severity badges
  - **JSON**: Full serialization with `default=str` for non-serializable types
  - **Terminal**: Colorized text output with severity bar visualization
- Charts generated with matplotlib (Agg backend for headless environments)

## Data Models

### LogEvent

```python
@dataclass
class LogEvent:
    timestamp: datetime
    source: str          # Log source type ("auth.log", "access.log", "syslog")
    raw: str             # Original raw log line
    parsed: dict[str, Any]  # Structured fields extracted by parser
    host: str            # Hostname from log line
```

### Alert

```python
@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str        # Critical, High, Medium, Low
    source_ip: str
    timestamp: datetime
    events: list[LogEvent]  # Evidence events
    description: str
    recommendation: str
    mitre_technique: str
    mitre_name: str
    count: int           # Number of matching events
```

### Report

```python
@dataclass
class Report:
    alerts: list[Alert]
    summary: dict
    total_events: int
    input_files: list[str]
    generated_at: datetime
    severity_breakdown: dict[str, int]
    rule_breakdown: dict[str, int]
    timeline: list[dict]
```

## Design Decisions

### Why YAML for Rules?
- Human-readable and editable without Python knowledge
- Easy to version control and diff
- Supports comments and complex nested structures
- No code changes needed to add/modify rules

### Why matplotlib over other libraries?
- Built-in with most Python distributions
- Agg backend works headless (no display required)
- Sufficient for static report charts (pie, bar, scatter)
- No additional infrastructure needed

### Why Jinja2 for HTML?
- Industry-standard templating for Python
- Template inheritance for future expansion
- Auto-escaping for security
- Clean separation between logic and presentation

### Why dataclasses for models?
- Immutable by convention (frozen=False)
- Built-in __repr__ and comparison
- Type hints for IDE support
- Lightweight — no ORM overhead

## File Structure

```
src/
├── __init__.py     # Package metadata (version: 1.0.0)
├── models.py       # LogEvent, Alert, Report dataclasses
├── parser.py       # Log parsers with source detection
├── detector.py     # DetectionEngine (threshold/pattern/correlation)
├── correlator.py   # AlertCorrelator (dedup, severity, report)
├── reporter.py     # Reporter (HTML, JSON, terminal output)
└── main.py         # CLI entry point with argparse

src/templates/
└── report.html     # Jinja2 HTML report template

config/
└── rules.yaml      # 7 detection rules (YAML)

tests/
├── test_parser.py      # 22 tests
├── test_detector.py    # 11 tests
├── test_correlator.py  # 11 tests
├── test_reporter.py    # 9 tests
└── test_main.py        # 9 tests (total: 62, coverage: 94%)
```
