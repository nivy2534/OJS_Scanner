import json
import asyncio
import os
import argparse

from .job_manager import JobManager
from .aggregator import aggregate

AVAILABLE_SCANNERS = ["crawler", "internal", "external_custom", "nuclei", "gobuster", "http_server"]

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path, encoding='utf-8') as f:
        return json.load(f)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Orchestrator for OJS scanning",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Example:
    python main.py                          -> Jalankan semua scan
    python main.py crawler                  -> Hanya crawler
    python main.py crawler nuclei           -> crawler + nuclei
    python main.py internal semgrep         -> internal + semgrep
    python main.py --list                   -> Tampilkan semua scan yang tersedia
"""
        )
    
    parser.add_argument(
        "scans",
        nargs="*",
        choices=AVAILABLE_SCANNERS + [""],
        help="Run scan. None = run all scans."
    )

    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="Show scan list"
    )

    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to custom config.json (optional)"
    )

    return parser.parse_args()

def build_scan_flags(requested_scan: list[str]) -> dict:
    """
    If there are no arguments -> all True.
    If there are arguments -> just listed is True.
    """
    run_all = len(requested_scan) == 0

    flags = {
        scan: True if run_all else (scan in requested_scan)
        for scan in AVAILABLE_SCANNERS
    }

    if any(flags[s] for s in AVAILABLE_SCANNERS if s!="http_server"):
        flags["http_server"] = True
    return flags

async def main():
    args = parse_args()

    if args.list:
        print("Available scan:")
        for scan in AVAILABLE_SCANNERS:
            print(f"  - {scan}")
        return

    os.makedirs("../results", exist_ok=True)

    config = load_config()

    scan_flags = build_scan_flags(args.scans)
    config["scans"] = scan_flags

    active_scans = [s for s, v in scan_flags.items() if v]
    print(f"[*] Running scan: {','.join(active_scans)}")

    manager = JobManager(config)

    try:
        await manager.execute()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        return

    findings = aggregate()

    print("\n=== FINAL FINDINGS ===")
    for f in findings:
        print(f)


if __name__ == "__main__":
    asyncio.run(main())