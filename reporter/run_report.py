"""
reporter/run_report.py

Entry point untuk generate security report.

Usage:
    python run_report.py
    python run_report.py --target http://localhost:9081 --results ../results
"""

from __future__ import annotations

import argparse
import os
import sys

from .findings_loader  import load_all_findings
from .template_builder import generate_report
from .notifier         import notify_if_needed


def main():
    parser = argparse.ArgumentParser(description="Generate OJS Security Report")
    parser.add_argument("--target",  default="", help="Target URL")
    parser.add_argument("--results", default="../results", help="Results directory")
    parser.add_argument("--no-notify", action="store_true", help="Skip notification")
    args = parser.parse_args()

    results_dir = os.path.abspath(args.results)
    print(f"[Reporter] Loading findings dari {results_dir}...")

    findings, scan_types = load_all_findings(results_dir)

    if not findings:
        print("[Reporter] Tidak ada findings — report tidak dibuat")
        return

    # Generate report
    report_path = generate_report(
        findings   = findings,
        target     = args.target,
        scan_types = scan_types,
        output_dir = os.path.join(results_dir, "reports"),
    )

    if not report_path:
        print("[Reporter] Gagal generate report")
        sys.exit(1)

    print(f"[Reporter] ✓ Report: {report_path}")

    # Notifikasi kalau ada findings yang risky
    if not args.no_notify:
        notify_if_needed(
            findings    = findings,
            report_path = report_path,
            target      = args.target,
        )


if __name__ == "__main__":
    main()
