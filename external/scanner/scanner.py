import requests
import re
import time
import urllib3
from urllib.parse import urlparse, parse_qs
from .payload_engine import apply_payload_url, get_fuzz_params
from .matcher import match_response
from .rule_loader import load_all_rules
from .modules.finger_print import FingerprintScanner
from ..utils.moduleLoader import load_module

urllib3.disable_warnings()


class Scanner:
    def __init__(self, session_manager):
        self.sm = session_manager
        self.session = session_manager.session
        self.session.verify = False

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

        self._anon_session = requests.Session()
        self._anon_session.verify = False
        self._anon_session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

        # Load konfigurasi OJS dari YAML 
        _ajax_cfg = load_module("ojs", "ajax_patterns")
        self._ajax_form_patterns = [
            e["pattern"] for e in _ajax_cfg.get("ajax_form_patterns", [])
        ]
        self._ajax_form_patterns_full = _ajax_cfg.get("ajax_form_patterns", [])
        self._grid_id_map   = _ajax_cfg.get("grid_id_map", {})
        self._grid_actions  = _ajax_cfg.get("grid_actions", {})
        self._verify_paths  = _ajax_cfg.get("verify_paths", {})
        self._trigger_pages = _ajax_cfg.get("trigger_pages_for_form_discovery", [])

    def _request(self, method, url, session=None, **kwargs):
        try:
            s = session if session is not None else (
                self.sm.session if self.sm is not None else self.session
            )
            start = time.time()
            r = s.request(method, url, timeout=10, **kwargs)
            elapsed = time.time() - start

            if r.encoding is None or r.encoding.lower() in ('charmap', 'cp1252', 'windows-1252'):
                r.encoding = 'utf-8'
            r._content
            try:
                r.encoding = 'utf-8'
                _ = r.text
            except (UnicodeDecodeError, LookupError):
                r.encoding = 'latin-1'
            return r, elapsed
        except Exception as e:
            print(f"[!] Request error {url}: {e}")
            return None, 0

    def _safe_text(self, r: requests.Response) -> str:
        try:
            return r.content.decode('utf-8', errors='replace')
        except Exception:
            return r.content.decode('latin-1', errors='replace')

    def _is_auth_response(self, r: requests.Response) -> bool:
        if r is None:
            return False
        body = self._safe_text(r)
        if "pkp_page_login" in body:
            return False
        if "login" in urlparse(r.url).path:
            return False
        return True

    def _get_verify_urls(self, base_url: str, action_url: str) -> list[str]:
        """
        Auto-detect category dari action_url lalu return verify URLs.
        Menggantikan hardcoded verify_urls di scan_form_xss.
        """
        for category, paths in self._verify_paths.items():
            if category == "default":
                continue
            if category in action_url.lower():
                return [base_url.rstrip("/") + "/" + p.lstrip("/") for p in paths]
        # fallback ke default
        default = self._verify_paths.get("default", [])
        return [base_url.rstrip("/") + "/" + p.lstrip("/") for p in default]

    def _get_base_url(self, url: str) -> str:
        """Ambil base URL (scheme://host/journal) dari URL apapun."""
        parsed = urlparse(url)
        parts = parsed.path.strip("/").split("/")
        journal = parts[0] if parts else ""
        return f"{parsed.scheme}://{parsed.netloc}/{journal}"

    def scan_fuzz(self, endpoints, rule):
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
                                self._safe_text(r), r.status_code, elapsed, rule["matchers"]
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
                    self._safe_text(r), r.status_code, elapsed, rule["matchers"]
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

    def _extract_ids(self, endpoints: list) -> dict:
        ids = {"submissions": set(), "issues": set(), "users": set()}
        for url in endpoints:
            patterns = {
                "submissions": [r'/submissions/(\d+)', r'/workflow/access/(\d+)'],
                "issues": [r'/issues/(\d+)', r'/issue/view/(\d+)'],
                "users": [r'/users/(\d+)'],
            }
            for resource, pats in patterns.items():
                for pat in pats:
                    m = re.search(pat, url)
                    if m:
                        ids[resource].add(int(m.group(1)))
        return {k: list(v) for k, v in ids.items()}

    def scan_idor(self, endpoints, base_url, journal, rule):
        findings = []
        known_ids = self._extract_ids(endpoints)
        tests = rule.get("tests", ["unauthenticated", "sequential"])

        if "unauthenticated" in tests:
            print(f"  [IDOR] Test unauthenticated access...")
            protected_patterns = rule.get("protected_patterns", [
                "/management/", "/submissions", "/manageIssues",
                "/stats/", "/workflow/", "/submission/wizard",
                "/api/v1/users", "/api/v1/_submissions", "/user/profile",
            ])

            for url in endpoints:
                path = urlparse(url).path
                if not any(p in path for p in protected_patterns):
                    continue

                r_anon, _ = self._request("GET", url, session=self._anon_session)
                if r_anon is None:
                    continue

                if self._is_auth_response(r_anon) and r_anon.status_code == 200:
                    try:
                        json_resp = r_anon.json()
                        if json_resp.get("status") == False:
                            continue
                    except:
                        pass

                    if len(self._safe_text(r_anon)) < 200:
                        continue

                    finding = {
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": "critical",
                        "url": url,
                        "status": r_anon.status_code,
                        "test_type": "unauthenticated-access",
                        "match": [f"Endpoint accessible without authentication (len={len(self._safe_text(r_anon))})"]
                    }
                    findings.append(finding)
                    print(f"  [CRITICAL] Unauth access: {url}")

                time.sleep(0.1)

        if "sequential" in tests and known_ids:
            print(f"  [IDOR] Test sequential ID enumeration...")

            templates = rule.get("id_templates", {
                "submissions": [
                    f"{base_url.rstrip('/')}/{journal}/api/v1/submissions/{{id}}",
                    f"{base_url.rstrip('/')}/{journal}/workflow/access/{{id}}",
                ],
                "issues": [
                    f"{base_url.rstrip('/')}/{journal}/api/v1/issues/{{id}}",
                    f"{base_url.rstrip('/')}/{journal}/issue/view/{{id}}",
                ],
                "users": [
                    f"{base_url.rstrip('/')}/{journal}/api/v1/users/{{id}}",
                ],
            })

            sensitive_words = rule.get("sensitive_words", [
                "email", "username", "password", "token",
                "submission", "author", "reviewer", "affiliation"
            ])

            for resource, ids in known_ids.items():
                if not ids:
                    continue

                max_id = max(ids)
                test_ids = list(range(1, max_id + 5)) + [0, -1, 99999]

                for tmpl in templates.get(resource, []):
                    for test_id in test_ids:
                        if test_id in ids and test_id > 0:
                            continue

                        url = tmpl.replace("{id}", str(test_id))
                        r, elapsed = self._request("GET", url)
                        if r is None:
                            continue

                        if r.status_code == 200 and len(r.text) > 200:
                            try:
                                json_resp = r.json()
                                if json_resp.get("status") == False:
                                    continue
                            except:
                                pass
                            has_sensitive = any(w in r.text.lower() for w in sensitive_words)
                            if has_sensitive:
                                finding = {
                                    "rule_id": rule["id"],
                                    "rule_name": rule["name"],
                                    "severity": rule.get("severity", "high"),
                                    "url": url,
                                    "status": r.status_code,
                                    "test_type": "sequential-enumeration",
                                    "match": [f"Resource ID {test_id} accessible with sensitive data"]
                                }
                                findings.append(finding)
                                print(f"  [HIGH] Sequential IDOR ID={test_id}: {url}")

                        time.sleep(0.1)

        return findings

    def get_version(self, base_url):
        print("[*] Running fingerprinting module...")
        fp = FingerprintScanner(base_url)
        server_version = fp._server_version
        ojs_version = fp._ojs_version
        print(f"  [Fingerprint] Server version: {server_version}")
        print(f"  [Fingerprint] OJS version: {ojs_version}")

    # Form XSS
    def _discover_ajax_forms(self, endpoints: list, patterns=None) -> list:
        # Pakai patterns dari YAML kalau tidak di-override
        if patterns is None:
            patterns = self._ajax_form_patterns

        found = []
        seen_loaders = set()

        # Pass 1: grep endpoint list untuk URL yang match pattern
        for url in endpoints:
            for pat in patterns:
                if re.search(pat, url, re.IGNORECASE):
                    if url not in seen_loaders:
                        seen_loaders.add(url)
                        found.append({"loader_url": url})

                    if 'grid' in url.lower():
                        base = url.split('?')[0].rstrip('/')
                        grid_name = base.split('/')[-1]

                        # Pakai grid_id_map dari YAML
                        grid_id = self._grid_id_map.get(grid_name)

                        # Pakai grid_actions dari YAML
                        actions = self._grid_actions.get(grid_name, [])
                        for action in actions:
                            derived = (
                                f"{base}/{action}?gridId={grid_id}"
                                if grid_id else f"{base}/{action}"
                            )
                            if derived not in seen_loaders:
                                seen_loaders.add(derived)
                                found.append({"loader_url": derived, "derived_from": url})

        # Pass 2: fetch trigger pages dan cari href yang match pattern
        trigger_pages = [
            u for u in endpoints
            if any(kw in u for kw in self._trigger_pages)
        ]

        for page_url in trigger_pages[:10]:
            r, _ = self._request("GET", page_url)
            if r is None:
                continue
            body = self._safe_text(r)
            grid_ids = re.findall(r'["\']([a-z]+-[a-z]+-[a-z]+grid)["\']', body)
            print(f"  [FormXSS] Found gridIds: {grid_ids}")
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', body)
            for href in hrefs:
                for pat in patterns:
                    if re.search(pat, href, re.IGNORECASE):
                        if href.startswith('http'):
                            loader = href
                        else:
                            parsed = urlparse(page_url)
                            loader = f"{parsed.scheme}://{parsed.netloc}{href}"
                        if loader not in seen_loaders:
                            seen_loaders.add(loader)
                            found.append({"loader_url": loader, "found_in": page_url})

        return found

    def _parse_ajax_form(self, loader_url: str) -> dict | None:
        parsed = urlparse(loader_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        journal = parsed.path.split('/')[1]
        referer = f"{base}/{journal}/manageIssues"

        req = requests.Request("GET", loader_url)
        prepared = self.session.prepare_request(req)
        #print(f"  [FormXSS] Cookie header actual: {prepared.headers.get('Cookie', 'TIDAK ADA')}")

        r, _ = self._request(
            "GET",
            loader_url,
            headers={
                "Referer": referer,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

        #print(f"  [FormXSS] cookie dikirim: {self.session.cookies.get_dict()}")
        #print(f"  [FormXSS] header cookie: {self.session.headers.get('Cookie', 'TIDAK ADA')}")

        if r is None or r.status_code != 200:
            print(f"  [FormXSS] status={r.status_code if r else 'None'} url={loader_url}")
            return None

        body = self._safe_text(r)
        print(f"  [FormXSS] status={r.status_code} len={len(body)} preview={body[:200]!r}")

        try:
            import json
            json_resp = json.loads(body)
            if not json_resp.get("status", False):
                return None
            html = json_resp.get("content", "")
            if not html:
                return None
        except (json.JSONDecodeError, ValueError):
            html = body

        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return self._parse_ajax_form_regex(html, loader_url)

        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        if not form:
            return None

        action = form.get("action", loader_url)
        method = form.get("method", "POST").upper()

        fields = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            val = inp.get("value", "")
            inp_type = inp.get("type", "text").lower()
            if inp_type in ("submit", "button", "image"):
                continue
            fields[name] = val

        return {
            "action": action,
            "method": method,
            "fields": fields,
            "csrf": fields.get("csrfToken", ""),
        }

    def _parse_ajax_form_regex(self, html: str, base_url: str) -> dict | None:
        form_match = re.search(r'<form\b[^>]*', html, re.IGNORECASE)
        if not form_match:
            return None

        form_tag = form_match.group(0)
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_tag, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_tag, re.IGNORECASE)

        action = action_match.group(1) if action_match else base_url
        method = method_match.group(1).upper() if method_match else "POST"

        fields = {}
        for m in re.finditer(
            r'<form[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
            html, re.IGNORECASE
        ):
            name, val = m.group(1), m.group(2) or ""
            inp_type = re.search(r'type=["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
            if inp_type and inp_type.group(1).lower() in ("submit", "button", "hidden"):
                if name != "csrfToken":
                    continue
            fields[name] = val

        for m in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE):
            fields[m.group(1)] = ""

        return {
            "action": action,
            "method": method,
            "fields": fields,
            "csrf": fields.get("csrfToken", ""),
        }

    def scan_form_xss(self, endpoints: list, rule: dict) -> list:
        findings = []

        # Patterns: dari rule dulu, fallback ke YAML
        ajax_patterns = rule.get("ajax_patterns") or self._ajax_form_patterns

        payloads = []
        fuzz_fields_pattern = None
        for req in rule.get("requests", []):
            for fuzz in req.get("fuzzing", []):
                payloads.extend(fuzz.get("payloads", []))
                fuzz_fields_pattern = fuzz.get("params_pattern")

        if not payloads:
            return findings

        print(f"  [FormXSS] Discovering AJAX form endpoints...")
        ajax_forms = self._discover_ajax_forms(endpoints, patterns=ajax_patterns)
        print(f"  [FormXSS] Found {len(ajax_forms)} potential form loader(s)")

        seen_findings = set()

        for form_info in ajax_forms:
            loader_url = form_info["loader_url"]
            print(f"  [FormXSS] Parsing form: {loader_url}")

            parsed = self._parse_ajax_form(loader_url)
            if not parsed:
                print(f"  [FormXSS] No form found at {loader_url}, skip")
                continue

            action_url = parsed["action"]
            method = parsed["method"]
            base_fields = parsed["fields"].copy()

            fuzzable = [
                fname for fname in base_fields
                if fname != "csrfToken" and (
                    not fuzz_fields_pattern or
                    re.search(fuzz_fields_pattern, fname, re.IGNORECASE)
                )
            ]

            print(f"  [FormXSS] Fuzzing {len(fuzzable)} field(s) on {action_url}")

            for field_name in fuzzable:
                for payload in payloads:
                    post_data = base_fields.copy()
                    post_data[field_name] = payload

                    r, elapsed = self._request(
                        method, action_url,
                        data=post_data,
                        allow_redirects=True,
                    )
                    if r is None:
                        continue

                    matched, result = match_response(
                        self._safe_text(r), r.status_code, elapsed, rule["matchers"]
                    )

                    if matched:
                        key = (field_name, payload[:30])
                        if key in seen_findings:
                            continue
                        seen_findings.add(key)

                        # Verify URLs dari YAML, bukan hardcoded
                        base_url = self._get_base_url(action_url)
                        verify_urls = self._get_verify_urls(base_url, action_url)

                        verified = False
                        for vurl in verify_urls:
                            vr, _ = self._request("GET", vurl)
                            if vr and payload in self._safe_text(vr):
                                verified = True
                                break

                        finding = {
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "severity": rule["severity"] if verified else "medium",
                            "url": action_url,
                            "loader_url": loader_url,
                            "param": field_name,
                            "payload": payload,
                            "status": r.status_code,
                            "match": result,
                            "verified": verified,
                            "test_type": "stored-xss" if verified else "potential-stored-xss",
                        }
                        findings.append(finding)
                        print(
                            f"[FOUND] [{rule['severity'].upper()}] {rule['name']} "
                            f"field={field_name} → {action_url}"
                        )

                    time.sleep(0.05)

        return findings

    def run(self, endpoints, base_url, journal, rule_ids=None):
        all_findings = []
        rules = load_all_rules(rule_ids)

        self.get_version(base_url)

        print(f"[*] Loaded {len(rules)} rules")

        for rule in rules:
            rtype = rule.get("type", "fuzz")
            print(f"[*] Running rule: {rule['id']} ({rtype})")

            if rtype == "form_xss":
                if self.sm is not None:
                    print(f"  [FormXSS] Re-authenticating...")
                    self.sm.force_refresh()
                all_findings.extend(self.scan_form_xss(endpoints, rule))
            elif rtype == "fuzz":
                all_findings.extend(self.scan_fuzz(endpoints, rule))
            elif rtype == "probe":
                all_findings.extend(self.scan_probe(base_url, journal, rule))
            elif rtype == "idor":
                all_findings.extend(self.scan_idor(endpoints, base_url, journal, rule))

        return all_findings
