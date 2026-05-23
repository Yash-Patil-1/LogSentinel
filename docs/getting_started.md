# Getting Started with LogSentinel

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/YashPatil/LogSentinel.git
cd LogSentinel

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install LogSentinel
pip install -e .

# Verify installation
logsentinel --version
```

### With Dev Dependencies

To install testing and development tools:

```bash
pip install -e ".[dev]"
```

## Quick Demo

Run LogSentinel on the bundled sample logs:

```bash
logsentinel --sample --verbose
```

This will:
1. Parse 3 sample log files (46 events total)
2. Run 7 detection rules
3. Correlate and deduplicate alerts
4. Generate HTML, JSON, and terminal reports

Reports are saved to `./reports/` by default.

## What's Next?

- [Usage Guide](usage.md) — Detailed CLI examples
- [Detection Rules](rules.md) — All 7 detection rules explained
- [Architecture](architecture.md) — Technical architecture overview
- [Development](development.md) — Contributing and extending
