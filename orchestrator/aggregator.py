import json
import os

def safe_load(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)

def aggregate():
    findings = []

    # nuclei
    nuclei = safe_load("../results/nuclei.json")
    for item in nuclei:
        findings.append({
            "source": "nuclei",
            "type": item.get("info", {}).get("name"),
            "severity": item.get("info", {}).get("severity"),
            "url": item.get("matched-at")
        })

    # custom external (kalau kamu output json juga)
    custom = safe_load("../results/custom.json")
    findings.extend(custom)

    return findings