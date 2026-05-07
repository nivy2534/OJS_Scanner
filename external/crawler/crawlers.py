from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urljoin, urldefrag, urlparse
import re
import json
from collections import deque
import time
import warnings
import requests
import urllib3
urllib3.disable_warnings()

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


class Crawlers:

    COMMON_ENDPOINTS = [
        "dashboard", "submissions", "manageIssues",
        "user/profile", "user/profile/roles",
        "login", "register",
        "management/settings/context",
        "management/settings/website",
        "management/settings/workflow",
        "management/settings/distribution",
        "management/settings/access",
        "management/tools",
        "stats/publications/publications",
        "stats/editorial/editorial",
        "stats/users/users",
        "stats/reports",
        "submission/wizard",
        "index/admin",
        "index/admin/contexts",
        "index/admin/settings",
        "index/admin/systemInfo",
        "index/admin/expireSessions",
        "index/admin/clearDataCache",
        "index/admin/clearTemplateCache",
        "api/v1/_submissions",
        "api/v1/users",
        "api/v1/issues",
        "$$$call$$$/grid/issues/back-issue-grid",
        "$$$call$$$/grid/issues/future-issue-grid",
        "$$$call$$$/grid/navigation-menus/navigation-menu-items-grid",
        "$$$call$$$/grid/navigation-menus/navigation-menus-grid",
        "$$$call$$$/grid/plugins/plugin-gallery-grid",
        "$$$call$$$/grid/settings/category/category-category-grid",
        "$$$call$$$/grid/settings/genre/genre-grid",
        "$$$call$$$/grid/settings/languages/manage-language-grid",
        "$$$call$$$/grid/settings/library/library-file-admin-grid",
        "$$$call$$$/grid/settings/plugins/settings-plugin-grid",
        "$$$call$$$/grid/settings/review-forms/review-form-grid",
        "$$$call$$$/grid/settings/roles/user-group-grid",
        "$$$call$$$/grid/settings/sections/section-grid",
        "$$$call$$$/grid/settings/user/user-grid",
        "$$$call$$$/grid/admin/context/context-grid",
    ]

    SKIP_URLS = [
        "signOut", "logout", "sign-out", "log-out"
    ]

    API_PATTERNS = [
        r"/api/v[0-9]+/[a-zA-Z0-9_/\-]+",
        r"/\$\$\$call\$\$\$/[a-zA-Z0-9/_\-]+",
    ]

    IGNORE_EXTENSIONS = (
        '.js', '.css', '.png', '.jpg', '.jpeg',
        '.ico', '.woff', '.woff2', '.ttf', '.svg', '.gif'
    )

    def __init__(self, domain, journal, sm=None, username=None, password=None):
        self.domain = domain.rstrip("/")
        self.journal = journal
        self.base = f"{self.domain}/{journal}/"
        self.visited = set()

        if sm:
            self.sm = sm
        else:
            from external.utils.session_manager import SessionManager
            self.sm = SessionManager(
                domain=domain,
                journal=journal,
                username=username,
                password=password
            )

        parsed = urlparse(self.domain)
        self.host = parsed.netloc

        # ✅ FIX 1: Pakai session dari SessionManager, bukan buat session baru
        self.session = self.sm.session
        self.session.headers.update({
            "Host": self.host,
            "Cache-Control": "max-age=0",
            "sec-ch-ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        })
        print(f"[*] Session initialized with cookies: {self.session.cookies.get_dict()}")

    def extract_menu_urls(self, html):
        """
        ✅ FIX 2: Ekstrak URL dari berbagai format OJS:
        - pkp.registry.init(...)   → menu JS lama
        - window.pkp.app           → format Vue/SPA baru
        - data-url / data-handler  → atribut HTML OJS
        """
        urls = set()

        # Format 1: pkp.registry.init — OJS 3.1/3.2
        for match in re.finditer(
            r'pkp\.registry\.init\([^,]+,\s*[^,]+,\s*(\{.*?\})\s*\);',
            html, re.DOTALL
        ):
            try:
                data = json.loads(match.group(1))
                self._walk_menu(data.get("menu", {}), urls)
                self._walk_menu(data.get("components", {}), urls)
            except Exception:
                pass

        # Format 2: window.pkp = {...} atau pkpState = {...} — OJS 3.3+
        for match in re.finditer(
            r'(?:window\.pkp|pkpState)\s*=\s*(\{.*?\});',
            html, re.DOTALL
        ):
            try:
                data = json.loads(match.group(1))
                self._walk_menu(data, urls)
            except Exception:
                pass

        # Format 3: Array menu JSON apapun yang punya key "url"
        for match in re.finditer(r'(\{[^{}]{0,2000}"url"\s*:\s*"http[^"]+?"[^{}]{0,2000}\})', html):
            try:
                data = json.loads(match.group(1))
                self._walk_menu(data, urls)
            except Exception:
                pass

        return urls

    def extract_data_attrs(self, soup):
        """✅ FIX 3: Ekstrak URL dari atribut data-* khas OJS."""
        urls = set()
        for tag in soup.find_all(True):
            for attr in ["data-url", "data-handler", "data-redirect"]:
                val = tag.get(attr, "")
                if val.startswith("http") and self.domain in val:
                    urls.add(val)
                elif val.startswith("/"):
                    urls.add(urljoin(self.domain, val))
        return urls

    def _walk_menu(self, menu, urls):
        """Rekursif telusuri dict/list dan kumpulkan semua URL."""
        if isinstance(menu, dict):
            for key, val in menu.items():
                if key == "url" and isinstance(val, str) and val.startswith("http"):
                    urls.add(val)
                else:
                    self._walk_menu(val, urls)
        elif isinstance(menu, list):
            for item in menu:
                self._walk_menu(item, urls)

    def is_noise(self, url):
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self.IGNORE_EXTENSIONS)

    def is_login_page(self, url):
        return "login" in urlparse(url).path
    
    def is_not_authenticated(self, response_text, url):
        """
        ✅ Lebih presisi — hanya anggap not-auth kalau SELURUH halaman adalah login page,
        bukan sekedar ada komponen login di dalamnya.
        """
        # Kalau ada konten utama selain login, berarti masih authenticated
        if "pkp_page_login" not in response_text:
            return False
        # Cek apakah ini benar-benar full redirect ke login
        parsed = urlparse(url)
        return "login" in parsed.path
    
    def in_scope(self, url):
        """Hanya crawl URL yang masih dalam domain dan journal."""
        parsed = urlparse(url)
        # ✅ Harus same host DAN path mulai dari /{journal}/ atau /index/
        path = parsed.path
        return (
            parsed.netloc == self.host and
            (path.startswith(f"/{self.journal}/") or path.startswith("/index/"))
        )

    def extract_api(self, text):
        results = set()
        for pattern in self.API_PATTERNS:
            for match in re.findall(pattern, text):
                full = urljoin(self.domain, match)
                if self.domain in full:
                    results.add(full)
        return results

    def enrich_endpoints(self):
        return {self.base + ep for ep in self.COMMON_ENDPOINTS}

    def discover_dynamic_urls(self, session):
        """Ekstrak URL dinamis dari API responses."""
        urls = set()
        
        # 1. Ambil submission IDs → generate wizard URLs
        try:
            r = session.get(f"{self.base}api/v1/_submissions?count=50&offset=0", 
                        verify=False, timeout=10)
            if r.status_code == 200:
                data = r.json()
                items = data.get("items", [])
                for item in items:
                    sid = item.get("id")
                    if sid:
                        # Wizard steps 1-5
                        for step in range(1, 6):
                            urls.add(f"{self.base}submission/wizard/{step}?submissionId={sid}")
                        # Workflow
                        urls.add(f"{self.base}workflow/access/{sid}")
                        # Publication
                        pub_id = item.get("currentPublicationId")
                        if pub_id:
                            urls.add(f"{self.base}api/v1/submissions/{sid}/publications/{pub_id}")
                print(f"[*] Found {len(items)} submissions → {len(urls)} dynamic URLs")
        except Exception as e:
            print(f"[!] Failed to get submissions: {e}")

        # 2. Ambil issue IDs
        try:
            r = session.get(f"{self.base}api/v1/issues?count=50&offset=0",
                        verify=False, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("items", []):
                    iid = item.get("id")
                    if iid:
                        urls.add(f"{self.base}issue/view/{iid}")
                        urls.add(f"{self.base}api/v1/issues/{iid}")
                print(f"[*] Found {len(data.get('items', []))} issues")
        except Exception as e:
            print(f"[!] Failed to get issues: {e}")

        # 3. Ambil user IDs
        try:
            r = session.get(f"{self.base}api/v1/users?count=50&offset=0",
                        verify=False, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("items", []):
                    uid = item.get("id")
                    if uid:
                        urls.add(f"{self.base}api/v1/users/{uid}")
                print(f"[*] Found {len(data.get('items', []))} users")
        except Exception as e:
            print(f"[!] Failed to get users: {e}")

        return urls

    def probe_enriched_endpoints(self):
        """
        ✅ FIX 4: Probe COMMON_ENDPOINTS secara aktif dan catat yang accessible.
        Ini penting karena endpoint admin tidak pernah muncul di HTML publik.
        """
        accessible = set()
        print("[*] Probing known admin endpoints...")
        
        self.sm._auto_refresh_enabled=False
        session = self.sm.session

        try:
            for url in self.enrich_endpoints():
                if url in self.visited:
                    continue
                try:
                    r = session.get(url, allow_redirects=True, verify=False, timeout=10)
                    final_url = r.url
                    status = r.status_code
                    is_auth = (
                        "pkp_page_login" not in r.text
                        and "login" not in urlparse(final_url).path
                    )
                    marker = "✓ auth" if is_auth else "✗ redirect-to-login"
                    print(f"  [{status}] {url} — {marker}")
                    if is_auth:
                        accessible.add(url)
                        self._parse_and_enqueue(url, r, depth=1)
                except Exception as e:
                    print(f"  [!] {url}: {e}")
                time.sleep(0.2)
            print("[*] Discovering dynamic URLs from API...")
            dynamic = self.discover_dynamic_urls(session)
            for url in dynamic:
                print(f"  [dynamic] {url}")
            accessible.update(dynamic)
        finally:
            # ✅ Selalu aktifkan kembali setelah probe selesai
            self.sm._auto_refresh_enabled = True

        return accessible

    def _parse_and_enqueue(self, url, response, depth):
        """Parse response dan masukkan URL baru ke visited + queue (dipakai probe)."""
        soup = BeautifulSoup(response.text, "html.parser")
        for found in self.extract_menu_urls(response.text):
            self._queued.add((found, depth + 1, url))
        for found in self.extract_data_attrs(soup):
            self._queued.add((found, depth + 1, url))
        for found in self.extract_api(response.text):
            self._queued.add((found, depth + 1, url))

    def crawl(self, max_depth=2):
        self._queued = set()   # buffer untuk _parse_and_enqueue
        queue = deque([(self.base, 0, None)])
        results = set()

        # ✅ Probe endpoint admin lebih dulu
        admin_urls = self.probe_enriched_endpoints()
        results.update(admin_urls)
        # Tambahkan URL temuan probe ke queue
        for item in self._queued:
            queue.append(item)
        self._queued.clear()

        while queue:
            url, depth, referer = queue.popleft()

            url_clean = urldefrag(url)[0]
            if url_clean in self.visited or depth > max_depth:
                continue

            if any(skip in url for skip in self.SKIP_URLS):
                print(f"[!] Skipping dangerous URL: {url}")
                continue

            self.visited.add(url_clean)

            if self.is_noise(url_clean):
                continue

            if referer:
                self.session.headers["Referer"] = referer
                self.session.headers["Sec-Fetch-Site"] = "same-origin"
            else:
                self.session.headers.pop("Referer", None)
                self.session.headers["Sec-Fetch-Site"] = "none"

            try:
                # ✅ Pakai self.sm.get agar auto-refresh session kalau expired
                r = self.sm.get(url_clean, allow_redirects=True)
            except Exception as e:
                print(f"[!] ERROR {url_clean}: {e}")
                continue

            print(f"[*] {url_clean} | {r.status_code}")

            if self.is_not_authenticated(r.text, url_clean):
                print(f"[!] Not authenticated: {url_clean}")
                continue   # skip parse — isinya cuma halaman login

            results.add(url_clean)

            soup = BeautifulSoup(r.text, "html.parser")

            # Menu JS OJS
            for menu_url in self.extract_menu_urls(r.text):
                if not self.is_noise(menu_url) and menu_url not in self.visited:
                    results.add(menu_url)
                    queue.append((menu_url, depth + 1, url_clean))

            # data-url / data-handler
            for du in self.extract_data_attrs(soup):
                if not self.is_noise(du) and du not in self.visited:
                    queue.append((du, depth + 1, url_clean))

            # API patterns
            results.update(self.extract_api(r.text))

            # Link biasa dari HTML
            for tag in soup.find_all(['a', 'form', 'link', 'script']):
                link = tag.get('href') or tag.get('src') or tag.get('action')
                if not link:
                    continue
                full = urldefrag(urljoin(url_clean, link))[0]
                if self.in_scope(full) and full not in self.visited and not self.is_noise(full):
                    queue.append((full, depth + 1, url_clean))

            time.sleep(0.3)

        # Tetap tambahkan semua COMMON_ENDPOINTS ke hasil (meski tidak accessible)
        results.update(self.enrich_endpoints())

        return sorted(results)