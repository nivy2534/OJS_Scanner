import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urljoin, urldefrag, urlparse
import re
import json
from collections import deque
import time
import warnings

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
    ]

    API_PATTERNS = [
        r"/api/v[0-9]+/[a-zA-Z0-9_/-]+",
        r"/\$\$\$call\$\$\$/[a-zA-Z0-9/_-]+",
    ]

    IGNORE_EXTENSIONS = (
        '.js', '.css', '.png', '.jpg', '.jpeg',
        '.ico', '.woff', '.woff2', '.ttf', '.svg', '.gif'
    )

    def __init__(self, domain, journal, cookie=None, username=None, password=None):
        self.domain = domain.rstrip("/")
        self.journal = journal
        self.base = f"{self.domain}/{journal}/"
        self.visited = set()

        parsed = urlparse(self.domain)
        self.host = parsed.netloc

        self.session = requests.Session()
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

        if username and password:
            success = self.login(username, password)
            if not success:
                print("[!] Login failed — check credentials")
        elif cookie:
            name, value = cookie.split("=", 1)
            self.session.cookies.set(
                name, value,
                domain=self.host.split(":")[0],
                path="/"
            )

    def login(self, username, password):
        login_url = f"{self.base}login"
        print(f"[*] Fetching login page: {login_url}")

        r = self.session.get(login_url, verify=False, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")

        csrf_input = soup.find("input", {"name": "csrfToken"})
        if not csrf_input:
            print("[!] CSRF token not found on login page")
            return False

        csrf = csrf_input.get("value")
        print(f"[*] CSRF token: {csrf}")

        self.session.headers["Referer"] = login_url
        self.session.headers["Sec-Fetch-Site"] = "same-origin"

        r = self.session.post(
            f"{self.base}login/signIn",
            data={"username": username, "password": password, "csrfToken": csrf},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
            timeout=10,
            allow_redirects=False
        )

        location = r.headers.get("Location", "")
        print(f"[*] Login redirect → {location}")

        if "login" in location or r.status_code != 302:
            print(f"[!] Login failed — location: {location}")
            return False

        self.session.get(
            urljoin(self.domain, location),
            verify=False, timeout=10, allow_redirects=True
        )

        session_cookie = self.session.cookies.get("OJSSID")
        print(f"[+] Login successful! OJSSID: {session_cookie}")
        return True

    def extract_menu_urls(self, html):
        """Extract URLs from OJS pkp.registry JSON embedded in page scripts."""
        urls = set()
        # Match the menu JSON inside pkp.registry.init(...)
        match = re.search(r'pkp\.registry\.init\([^,]+,\s*[^,]+,\s*(\{.*?\})\s*\);', html, re.DOTALL)
        if not match:
            return urls
        try:
            data = json.loads(match.group(1))
            menu = data.get("menu", {})
            self._walk_menu(menu, urls)
        except Exception:
            pass
        return urls

    def _walk_menu(self, menu, urls):
        """Recursively walk menu/submenu and collect all URLs."""
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

    def extract_api(self, text):
        results = set()
        for pattern in self.API_PATTERNS:
            for match in re.findall(pattern, text):
                results.add(urljoin(self.domain, match))
        return results

    def enrich_endpoints(self):
        return {self.base + ep for ep in self.COMMON_ENDPOINTS}

    def crawl(self, max_depth=2):
        queue = deque([(self.base, 0, None)])
        results = set()

        while queue:
            url, depth, referer = queue.popleft()

            if url in self.visited or depth > max_depth:
                continue

            self.visited.add(url)

            if self.is_noise(url):
                continue

            if referer:
                self.session.headers["Referer"] = referer
                self.session.headers["Sec-Fetch-Site"] = "same-origin"
            else:
                self.session.headers.pop("Referer", None)
                self.session.headers["Sec-Fetch-Site"] = "none"

            try:
                r = self.session.get(url, verify=False, timeout=5, allow_redirects=True)
            except Exception as e:
                print(f"[!] ERROR {url}: {e}")
                continue

            print(f"[*] {url} | {r.status_code}")

            if "pkp_page_login" in r.text and not self.is_login_page(url):
                print(f"[!] Not authenticated at: {url}")

            results.add(url)

            # Extract menu URLs from embedded JS JSON (replaces Playwright nav extraction)
            for menu_url in self.extract_menu_urls(r.text):
                if not self.is_noise(menu_url) and menu_url not in self.visited:
                    results.add(menu_url)
                    queue.append((menu_url, depth + 1, url))

            # Extract API endpoints from page source
            results.update(self.extract_api(r.text))

            # Extract links from HTML
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all(['a', 'form', 'link', 'script']):
                link = tag.get('href') or tag.get('src') or tag.get('action')
                if not link:
                    continue
                full = urldefrag(urljoin(url, link))[0]
                if self.domain in full and full not in self.visited and not self.is_noise(full):
                    queue.append((full, depth + 1, url))

            time.sleep(0.3)

        # Add known endpoints
        results.update(self.enrich_endpoints())

        return sorted(results)