# scanner.py
from playwright.sync_api import sync_playwright
from urllib.parse import urlparse, parse_qs
from scanner.payload_engine import apply_payload
from scanner.matcher import match_response

class Scanner:

    def __init__(self, storage_state):
        self.storage_state = storage_state

    def scan(self, endpoints, rule):
        findings = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(storage_state=self.storage_state)

            for endpoint in endpoints:
                parsed = urlparse(endpoint)
                params = parse_qs(parsed.query)

                if not params:
                    continue

                for req in rule["requests"]:
                    fuzzing = req.get("fuzzing", [])

                    for fuzz in fuzzing:
                        mode = fuzz.get("mode", "replace")
                        payloads = fuzz["payloads"]

                        for param in params.keys():
                            for payload in payloads:

                                test_url = apply_payload(endpoint, param, payload, mode)

                                if not test_url:
                                    continue

                                page = context.new_page()

                                try:
                                    page.goto(test_url, timeout=5000)
                                    content = page.content()

                                    result = match_response(content, rule["matchers"])

                                    if result:
                                        findings.append({
                                            "url": test_url,
                                            "param": param,
                                            "payload": payload,
                                            "match": result
                                        })

                                        print(f"[🔥 FOUND] {test_url}")

                                except Exception as e:
                                    print("ERROR:", e)

                                finally:
                                    page.close()

            browser.close()

        return findings