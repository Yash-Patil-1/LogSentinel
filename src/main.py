"""
LogSentinel - CLI Entry Point

Command-line tool for log analysis and threat detection.
Orchestrates the full pipeline: parse -> detect -> correlate -> report.

Usage:
    python -m src.main sample_logs/auth.log
    python -m src.main sample_logs/*.log --format html
    python -m src.main sample_logs/auth.log --source auth.log --output-dir ./reports
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import LogEvent
from .parser import parse_file
from .detector import DetectionEngine
from .correlator import AlertCorrelator
from .reporter import Reporter
from . import __version__, __author__


def find_default_rules() -> Optional[str]:
    """Locate the default rules.yaml relative to the project root."""
    # Look relative to this script's location
    script_dir = Path(__file__).resolve().parent.parent
    candidates = [
        script_dir / "config" / "rules.yaml",
        Path.cwd() / "config" / "rules.yaml",
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    return None


def find_sample_logs() -> list[str]:
    """Locate sample log files relative to the project root."""
    script_dir = Path(__file__).resolve().parent.parent
    candidates = [
        script_dir / "sample_logs",
        Path.cwd() / "sample_logs",
    ]
    for sample_dir in candidates:
        if sample_dir.exists():
            log_files = sorted(p for p in sample_dir.iterdir() if p.is_file())
            if log_files:
                return [str(p) for p in log_files]
    return []


def run_pipeline(
    log_files: list[str],
    rules_config: Optional[str] = None,
    output_dir: str = "./reports",
    source_hint: Optional[str] = None,
    verbose: bool = False,
) -> dict[str, str]:
    """
    Execute the full LogSentinel pipeline.

    Args:
        log_files: List of paths to log files.
        rules_config: Path to rules YAML config. Defaults to config/rules.yaml.
        output_dir: Directory for generated reports.
        source_hint: Optional log source override.
        verbose: If True, print progress information.

    Returns:
        Dict mapping format names to output file paths.
    """
    if verbose:
        print(f"[+] LogSentinel v1.0.0 - Security Analysis Pipeline")
        print(f"[+] Input files: {', '.join(log_files)}")
        print(f"")

    # ── Stage 1: Parse ──
    if verbose:
        print(f"[*] Stage 1/4: Parsing log files...")

    all_events: list[LogEvent] = []
    parsed_count = 0
    skipped_count = 0

    for filepath in log_files:
        if not os.path.exists(filepath):
            if verbose:
                print(f"  [!] Skipping (not found): {filepath}")
            continue

        file_events = []
        for event in parse_file(filepath, source_hint):
            file_events.append(event)
            all_events.append(event)

        parsed_count += len(file_events)
        if verbose:
            print(f"  [ ] Parsed {len(file_events):>4} events from {os.path.basename(filepath)}")

    if not all_events:
        print(f"[!] No events could be parsed from the provided log files.")
        return {}

    if verbose:
        print(f"  [+] Total: {parsed_count} events parsed")
        print(f"")

    # ── Stage 2: Detect ──
    if verbose:
        print(f"[*] Stage 2/4: Running detection engine...")

    rules = rules_config or find_default_rules()
    if not rules:
        print("[!] No rules configuration found. Provide --rules or ensure config/rules.yaml exists.")
        return {}

    engine = DetectionEngine(rules)
    raw_alerts = engine.analyze_events(all_events)

    if verbose:
        print(f"  [+] {len(raw_alerts)} raw alerts generated")
        print(f"")

    # ── Stage 3: Correlate ──
    if verbose:
        print(f"[*] Stage 3/4: Correlating alerts...")

    correlator = AlertCorrelator()
    processed_alerts = correlator.process(raw_alerts)
    report = correlator.generate_report(
        alerts=processed_alerts,
        total_events=parsed_count,
        input_files=log_files,
    )

    if verbose:
        print(f"  [+] {len(processed_alerts)} alerts after correlation")
        print(f"")

    # ── Stage 4: Report ──
    if verbose:
        print(f"[*] Stage 4/4: Generating reports...")

    reporter = Reporter(output_dir=output_dir)
    report_name = f"logsentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_paths = reporter.generate_all(report, report_name)

    if verbose:
        for fmt, path in output_paths.items():
            rel_path = os.path.relpath(path, os.getcwd())
            print(f"  [+] {fmt.upper():>8}: {rel_path}")
        print(f"")
        print(f"[+] Analysis complete.")

    return output_paths


def main():
    """CLI entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description="LogSentinel - Log Analysis & Threat Detection Engine",
        epilog="Examples:\n"
        "  %(prog)s sample_logs/auth.log\n"
        "  %(prog)s sample_logs/*.log --format html\n"
        "  %(prog)s /var/log/auth.log --output-dir ./reports --verbose\n"
        "  %(prog)s --sample    # Analyze sample logs\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "log_files",
        nargs="*",
        help="Path(s) to log file(s) to analyze. Defaults to sample_logs/*.log if not provided.",
    )

    parser.add_argument(
        "--sample",
        action="store_true",
        help="Analyze bundled sample log files (overrides any log_files argument).",
    )

    parser.add_argument(
        "--rules",
        "-r",
        help="Path to detection rules YAML config (default: config/rules.yaml).",
    )

    parser.add_argument(
        "--output-dir",
        "-o",
        default="./reports",
        help="Directory to save generated reports (default: ./reports).",
    )

    parser.add_argument(
        "--source",
        "-s",
        choices=["auth.log", "access.log", "syslog"],
        help="Override log source auto-detection for all files.",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["html", "json", "terminal", "all"],
        default="all",
        help="Output format (default: all).",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed progress during analysis.",
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit.",
    )

    args = parser.parse_args()

    if args.version:
        print(f"LogSentinel v{__version__}")
        sys.exit(0)

    # Determine log files
    log_files: list[str] = args.log_files if args.log_files else []

    if args.sample or not log_files:
        samples = find_sample_logs()
        if samples:
            if args.verbose or not log_files:
                print(f"[+] Using sample logs: {', '.join(os.path.basename(s) for s in samples)}")
            log_files = samples
        elif not log_files:
            parser.print_help()
            print(f"\n[!] No log files provided and no sample logs found.")
            print(f"    Provide log file paths or create sample_logs/ directory.")
            sys.exit(1)

    # Run the pipeline
    output_paths = run_pipeline(
        log_files=log_files,
        rules_config=args.rules,
        output_dir=args.output_dir,
        source_hint=args.source,
        verbose=args.verbose,
    )

    if not output_paths:
        sys.exit(1)

    # If a specific format was requested, only show that one
    if args.format != "all":
        for fmt in list(output_paths.keys()):
            if fmt != args.format:
                del output_paths[fmt]

    if not args.verbose:
        for fmt, path in output_paths.items():
            rel_path = os.path.relpath(path, os.getcwd())
            print(f"[+] {fmt.upper()} report: {rel_path}")


if __name__ == "__main__":
    main()
