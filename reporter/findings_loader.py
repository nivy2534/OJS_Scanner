"""
reporter/findings_loader.py

Load dan gabungkan semua findings dari results/ directory.
Ambil file terbaru per type berdasarkan timestamp di nama file.
"""

from __future__ import annotations

import glob
import json
import os
import re
from datetime import datetime


RESULTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../results")
)


def _get_latest_file(pattern: str) -> str | None:
    """Ambil file terbaru berdasarkan timestamp di nama file."""
    files = glob.glob(pattern)
    if not files:
        return None

    def extract_ts(path):
        # Coba extract timestamp dari nama file: semgrep_20260518174220.json
        match = re.search(r"(\d{14})", os.path.basename(path))
        if match:
            return match.group(1)
        # Fallback ke mtime
        return str(int(os.path.getmtime(path)))

    return max(files, key=extract_ts)


def load_scanner_findings(results_dir: str = RESULTS_DIR) -> list[dict]:
    """Load findings dari scanner.json (DAST)."""
    path = os.path.join(results_dir, "scanner.json")
    if not os.path.exists(path):
        return []

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        # Tambah source tag
        for item in data:
            item.setdefault("source", "dast")
        return data
    except Exception as e:
        print(f"[Loader] Gagal load scanner.json: {e}")
        return []


def load_semgrep_findings(results_dir: str = RESULTS_DIR) -> list[dict]:
    """Load findings dari semgrep_{ts}.json terbaru (SAST)."""
    pattern = os.path.join(results_dir, "semgrep_*.json")
    latest  = _get_latest_file(pattern)

    if not latest:
        return []

    try:
        with open(latest, encoding="utf-8") as f:
            data = json.load(f)

        # Semgrep output punya format berbeda — normalisasi
        results = data.get("results", data) if isinstance(data, dict) else data
        findings = []
        for item in results:
            findings.append({
                "source":    "sast",
                "rule_id":   item.get("type") or item.get("check_id", ""),
                "severity":  _map_semgrep_severity(item.get("severity", "WARNING")),
                "file":      item.get("file") or item.get("path", ""),
                "line":      item.get("line") or item.get("start", {}).get("line"),
                "message":   item.get("message", ""),
                "rule_name": item.get("type") or item.get("check_id", ""),
            })
        return findings
    except Exception as e:
        print(f"[Loader] Gagal load semgrep findings: {e}")
        return []


def load_agent_findings(results_dir: str = RESULTS_DIR) -> list[dict]:
    """Load findings dari agent_scan_{ts}.json terbaru (SAST via agent)."""
    pattern = os.path.join(results_dir, "agent_scan_*.json")
    latest  = _get_latest_file(pattern)

    if not latest:
        return []

    try:
        with open(latest, encoding="utf-8") as f:
            data = json.load(f)

        findings = data.get("findings", [])
        for item in findings:
            item.setdefault("source", "sast")
        return findings
    except Exception as e:
        print(f"[Loader] Gagal load agent findings: {e}")
        return []


def load_all_findings(results_dir: str = RESULTS_DIR) -> tuple[list[dict], list[str]]:
    """
    Load dan gabungkan semua findings.
    Return: (findings, scan_types)
    """
    all_findings = []
    scan_types   = []

    dast = load_scanner_findings(results_dir)
    if dast:
        all_findings.extend(dast)
        scan_types.append("dast")
        print(f"[Loader] DAST: {len(dast)} findings")

    sast = load_semgrep_findings(results_dir)
    if sast:
        all_findings.extend(sast)
        if "sast" not in scan_types:
            scan_types.append("sast")
        print(f"[Loader] SAST (semgrep): {len(sast)} findings")

    agent = load_agent_findings(results_dir)
    if agent:
        all_findings.extend(agent)
        if "sast" not in scan_types:
            scan_types.append("sast")
        print(f"[Loader] SAST (agent): {len(agent)} findings")

    print(f"[Loader] Total: {len(all_findings)} findings dari {scan_types}")
    return all_findings, scan_types


def _map_semgrep_severity(sev: str) -> str:
    return {
        "ERROR":   "high",
        "WARNING": "medium",
        "INFO":    "low",
    }.get(sev.upper(), "info")
