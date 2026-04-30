import requests
import time
import urllib3
from urllib.parse import urlparse, parse_qs
from .payload_engine import apply_payload_url, get_fuzz_params
from .matcher import match_response
from .rule_loader import load_all_rules

urllib3.disable_warnings()


class Scanner:
    def __init__(self, session: requests.Session):
        self.session = session
        self.session.verify = False

        if self.session.cookies:
            self.session.headers.update({"Cookie": "; ".join(f"{c.name}={c.value}" for c in self.session.cookies)})

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

    def _request(self, method, url, **kwargs):
        try:
            start = time.time()
            r = self.session.request(method, url, timeout=10, **kwargs)
            elapsed = time.time() - start
            return r, elapsed
        except Exception as e:
            print(f"[!] Request error {url}: {e}")
            return None, 0

    def scan_fuzz(self, endpoints, rule):
        """Fuzz query params atau body."""
        findings = []

        for endpoint in endpoints:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)

            for req in rule["requests"]:
                method = req.get("method", "GET").upper()
                fuzzing = req.get("fuzzing", [])

                for fuzz in fuzzing:
                    mode = fuzz.get("mode", "replace")
                    payloads = fuzz["payloads"]
                    param_pattern = fuzz.get("params_pattern")

                    target_params = get_fuzz_params(params, param_pattern)

                    for param in target_params:
                        for payload in payloads:
                            test_url = apply_payload_url(endpoint, param, payload, mode)
                            if not test_url:
                                continue

                            r, elapsed = self._request(method, test_url)
                            if r is None:
                                continue

                            matched, result = match_response(
                                r.text, r.status_code, elapsed, rule["matchers"]
                            )

                            if matched:
                                finding = {
                                    "rule_id": rule["id"],
                                    "rule_name": rule["name"],
                                    "severity": rule["severity"],
                                    "url": test_url,
                                    "param": param,
                                    "payload": payload,
                                    "status": r.status_code,
                                    "match": result
                                }
                                findings.append(finding)
                                print(f"[FOUND] [{rule['severity'].upper()}] {rule['name']} → {test_url}")

        return findings

    def scan_probe(self, base_url, journal, rule):
        """Hit path langsung tanpa fuzzing (untuk broken auth dll)."""
        findings = []

        for req in rule["requests"]:
            method = req.get("method", "GET").upper()
            paths = req.get("paths", [])

            for path in paths:
                path = path.replace("{journal}", journal)
                url = base_url.rstrip("/") + "/" + path.lstrip("/")

                r, elapsed = self._request(method, url)
                if r is None:
                    continue

                matched, result = match_response(
                    r.text, r.status_code, elapsed, rule["matchers"]
                )

                if matched:
                    finding = {
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "url": url,
                        "status": r.status_code,
                        "match": result
                    }
                    findings.append(finding)
                    print(f"[FOUND] [{rule['severity'].upper()}] {rule['name']} → {url}")

        return findings

    def run(self, endpoints, base_url, journal, rule_ids=None):
        """Entry point utama — load rules dan jalankan semua scan."""
        all_findings = []
        rules = load_all_rules(rule_ids)

        print(f"[*] Loaded {len(rules)} rules")

        for rule in rules:
            rtype = rule.get("type", "fuzz")
            print(f"[*] Running rule: {rule['id']} ({rtype})")

            if rtype == "fuzz":
                all_findings.extend(self.scan_fuzz(endpoints, rule))
            elif rtype == "probe":
                all_findings.extend(self.scan_probe(base_url, journal, rule))

        return all_findings