# Development Guide

## Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/Yash-Patil-1/LogSentinel.git
cd LogSentinel

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Verify installation
python3 -m pytest tests/ -v
```

## Project Structure

```
src/
├── __init__.py       # Package metadata
├── models.py         # LogEvent, Alert, Report dataclasses
├── parser.py         # Log parsers
├── detector.py       # Detection engine
├── correlator.py     # Alert correlator
├── reporter.py       # Report generator
└── main.py           # CLI entry point
```

## Running Tests

```bash
# Run all tests
python3 -m pytest tests/

# Run with verbose output
python3 -m pytest tests/ -v

# Run with coverage report
python3 -m pytest tests/ --cov=src --cov-report=term-missing

# Run specific test file
python3 -m pytest tests/test_detector.py -v

# Run specific test
python3 -m pytest tests/test_detector.py::TestDetectionEngine::test_ssh_brute_force_det001 -v
```

## Building the Package

```bash
# Install build tools
pip install build

# Build wheel and source distribution
python3 -m build

# Check the built distribution
ls dist/
# logsentinel-1.0.0.tar.gz
# logsentinel-1.0.0-py3-none-any.whl
```

## Adding a New Detection Rule

### 1. Update rules.yaml

Add a new rule to `config/rules.yaml`:

```yaml
- rule_id: "DET-008"
  title: "New Attack"
  description: "Description of the attack pattern."
  severity: "High"
  log_source: "auth.log"
  mitre_technique: "TXXXX"
  mitre_name: "Technique Name"
  detection_type: "threshold"
  conditions:
    event_type: "some_event"
    threshold: 5
    time_window_seconds: 60
  recommendation: "Recommendation for response."
```

### 2. (Optional) Update parser

If the new rule requires fields not currently extracted by the parser, modify the relevant parser in `src/parser.py`.

### 3. Add tests

Add test cases in the appropriate test file:

```python
def test_new_rule_det008(self):
    events = [
        self._make_event("auth.log", "some_event", "10.0.0.5"),
    ]
    alerts = self.engine.analyze_events(events)
    det008 = [a for a in alerts if a.rule_id == "DET-008"]
    assert len(det008) > 0
    assert det008[0].severity == "High"
```

### 4. Run tests

```bash
python3 -m pytest tests/ -v
```

## Adding a New Log Parser

### 1. Create the parser function

In `src/parser.py`, add a new parsing function:

```python
def parse_new_log(line: str, regex: Pattern) -> Optional[dict]:
    match = regex.search(line)
    if not match:
        return None
    return {
        "event_type": "new_event",
        "ip": match.group("ip"),
        "field1": match.group("field1"),
        "field2": match.group("field2"),
    }
```

### 2. Register the parser

Update the `SOURCE_PATTERNS` and `PARSER_REGISTRY` in `src/parser.py`.

### 3. Add detection rules

Add rules that target the new log source in `config/rules.yaml`.

### 4. Add test cases

Test parsing of sample log lines and test detection rules.

## Code Style

- Follow PEP 8 conventions
- Use type hints for all function signatures
- Write docstrings for all public methods
- Keep functions focused and single-purpose
- Use dataclasses for data containers

## Testing Guidelines

- Aim for 90%+ code coverage
- Test edge cases (empty input, invalid format, boundary conditions)
- Use fixtures and setup methods for reusable test data
- Name tests descriptively: `test_[feature]_[condition]_[expected]`
- Test both positive (alert fires) and negative (no alert) cases

## Release Process

1. Update version in `src/__init__.py`
2. Update `pyproject.toml` version
3. Run full test suite
4. Build package: `python3 -m build`
5. Verify the wheel installs cleanly
6. Tag the release in git
