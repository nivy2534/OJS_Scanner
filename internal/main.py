import os
import json
import subprocess
import shutil
from glob import glob
from datetime import datetime

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
SEMGREP = shutil.which("semgrep")

def load_rule(path=None):
    rules = []

    if path:
        if os.path.isfile(path):
            rules.append(path)
    else:
        rules.extend(glob(os.path.join(RULES_DIR, "*.yaml")))
        rules.extend(glob(os.path.join(RULES_DIR, "*.yml")))
    return rules

def run_semgrep(target, rules):
    output_file = get_output_file()

    rule_args = " ".join([f'-c "{r}"' for r in rules])
    cmd = f'{SEMGREP} {rule_args} --json --no-git-ignore "{target}" > "{output_file}"'

    print(f"[DEBUG] semgrep cmd: {cmd}")  
    print(f"[DEBUG] semgrep path: {SEMGREP}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    print(f"[DEBUG] semgrep returncode: {result.returncode}")
    print(f"[DEBUG] semgrep stdout: {result.stdout}")
    print(f"[DEBUG] semgrep stderr: {result.stderr}")

    if result.returncode not in [0,1]:  # semgrep returns 1 if it finds issues
        raise RuntimeError(f"Error running semgrep: {result.stderr}")
    return output_file

def get_output_file():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"semgrep_{timestamp}.json"
    results_dir = os.path.join(os.path.dirname(__file__), "../results")
    os.makedirs(results_dir, exist_ok=True)  
    return os.path.join(results_dir, filename)

def parse_result(path):
    """
    Normalisasi hasil semgrep
    """
    if not os.path.exists(path):
        return []

    with open(path) as f:
        data = json.load(f)

    findings = []

    for item in data.get("results", []):
        findings.append({
            "type": item.get("check_id"),
            "severity": item.get("extra", {}).get("severity"),
            "file": item.get("path"),
            "line": item.get("start", {}).get("line"),
            "message": item.get("extra", {}).get("message"),
            "source": "semgrep"
        })

    return findings

def scan(target):
    print("[*] Internal scan (Semgrep) running...")

    rules = load_rule()

    if not rules:
        print("[*] No custom rules found, using default rules")
        rules = ["p/php"]

    output_path = run_semgrep(target, rules)

    findings = parse_result(output_path)

    return findings

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/ojs-source")
    results = scan(target)

    print("\n=== SEMGREP RESULTS ===")
    for r in results:
        print(r)
