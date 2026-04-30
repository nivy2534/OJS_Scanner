# test_pw_crawl.py
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag, urlparse
from collections import deque

domain = "http://localhost:8081"
journal = "coba"
username = "admin"
password = "OJS_Scanner_1"

IGNORE_EXTENSIONS = (
    '.js', '.css', '.png', '.jpg', '.jpeg',
    '.ico', '.woff', '.woff2', '.ttf', '.svg', '.gif'
)

def is_noise(url):
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in IGNORE_EXTENSIONS)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    # Login
    print("[*] Logging in...")
    page.goto(f"{domain}/{journal}/login")
    page.fill("input[name='username']", username)
    page.fill("input[name='password']", password)
    page.click("button[type='submit']")
    page.wait_for_load_state("networkidle")
    print(f"[*] After login: {page.url}")

    # Simpan auth
    context.storage_state(path="auth.json")

    # Test akses admin
    page.goto(f"{domain}/{journal}/management/settings/context")
    page.wait_for_load_state("networkidle")
    print(f"[*] management/settings/context → {page.url}")
    print(f"[*] pkp_page_login: {'pkp_page_login' in page.content()}")

    # BFS crawl
    visited = set()
    results = []
    queue = deque([f"{domain}/{journal}/"])

    while queue:
        url = queue.popleft()
        if url in visited or is_noise(url):
            continue
        visited.add(url)

        try:
            page.goto(url, timeout=8000, wait_until="domcontentloaded")
        except Exception as e:
            print(f"[!] {url}: {e}")
            continue

        current = page.url
        print(f"[*] {url} → {current}")
        results.append(url)

        soup = BeautifulSoup(page.content(), "html.parser")
        for tag in soup.find_all(['a', 'form', 'link', 'script']):
            link = tag.get('href') or tag.get('src') or tag.get('action')
            if not link:
                continue
            full = urldefrag(urljoin(url, link))[0]
            if domain in full and full not in visited and not is_noise(full):
                queue.append(full)

    browser.close()

print(f"\n[+] Total: {len(results)} URLs")
for r in sorted(results):
    print(r)