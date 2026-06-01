import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag
import re
from collections import deque
from playwright.sync_api import sync_playwright

class Crawler:

    COMMON_ENDPOINTS = [
        "dashboard",
        "submissions",
        "user/profile",
        "user/profile/roles",
        "login",
        "register",
        "api/v1/_submissions",
        "api/v1/users",
        "api/v1/issues",
    ]

    API_PATTERNS = [
        r"/api/v[0-9]+/[a-zA-Z0-9_/-]+",
        r"/\$\$\$call\$\$\$/[a-zA-Z0-9/_-]+",
    ]

    def __init__(self, domain, journal):
        self.domain = domain.rstrip("/")
        self.journal = journal
        self.base = f"{self.domain}/{journal}/"
        self.visited = set()
        
    def inject_cookies(self, cookies):
        for name, value in cookies.items():
            self.session.cookies.set(
                name,
                value,
                domain="localhost",
                path="/"
            )

    def regex(self, text):
        results = []
        for pattern in self.API_PATTERNS:
            results += re.findall(pattern, text)
        return results

    def enrich_endpoints(self, base):
        return [base + ep for ep in self.COMMON_ENDPOINTS]

    def crawl(self, auth_file):
        domain = self.domain
        journal = self.journal
        visited = set()
        results = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            
            context = browser.new_context(storage_state=auth_file)
            page = context.new_page()

            # BFS crawl
            queue = deque([f"{domain}/{journal}/"])

            while queue:
                url = queue.popleft()

                if url in visited:
                    continue

                visited.add(url)

                try:
                    page.goto(url, timeout=5000)
                except:
                    continue

                print(url)
                results.append(url)

                html = page.content()

                soup = BeautifulSoup(html, "html.parser")

                for tag in soup.find_all(['a','form','link','script']):
                    link = tag.get('href') or tag.get('src') or tag.get('action')
                    if not link:
                        continue

                    full = urljoin(url, link)
                    full = urldefrag(full)[0]

                    if domain in full and full not in visited:
                        queue.append(full)

            PROBE_ENDPOINTS = [
                "management/settings/context", "management/settings/website",
                "management/settings/workflow", "management/settings/distribution",
                "management/settings/access", "management/tools",
                "stats/publications/publications", "stats/editorial/editorial",
                "stats/users/users", "stats/reports", "submissions", "manageIssues",
                "submission/wizard",
            ]

            print("\n[*] Probing admin endpoints...")
            for ep in PROBE_ENDPOINTS:
                url = f"{domain}/{journal}/{ep}"
                if url in visited:
                    continue
                page.goto(url, wait_until="domcontentloaded")
                final = page.url
                is_auth = "login" not in final
                print(f"  {'✓' if is_auth else '✗'} {url} → {final}")
                if is_auth:
                    results.append(url)
            
            browser.close()

        return results

    def extract_profile(self, url):
        parts = url.split("/")
        if len(parts) > 3:
            return "/" + parts[3] + "/"
        return None
    
    def signOut(self, journal):
        url = self.domain + f"/{journal}/login/signOut"
        r = self.session.get(url)
        print(f"SignOut. Deleting cookies: {r.cookies}")

        print(f"this is the r cookies {r.cookies.get_dict()}")
        print(f"this is the saved cookies {self.session.cookies.get_dict()}")
        if self.session.cookies.get_dict() not in r.cookies:
            self.session = requests.session()
            print(f"session deleted")
            print(self.session.cookies.get_dict())
    
    def reset_session(self):
        self.session = requests.Session()