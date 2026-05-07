import requests
import re
from bs4 import BeautifulSoup

class FingerprintScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()

        self.r, _ = self._get(self.base_url)
        self._versions_result = self._print_version(self.r)
        self._server_version = self._versions_result[0]
        self._ojs_version = self._versions_result[1] if len(self._versions_result) > 1 else None

    def _request(self, method, url):
        try:
            r = self.session.request(method, url, timeout=10, verify=False)
            return r, r.elapsed.total_seconds()
        except requests.RequestException as e:
            print(f"[ERROR] Request to {url} failed: {e}")
            return None, None
        
    def _get(self, url):
        return self._request("GET", url)
    
    def _print_version(self, r):
        versions = []
        if r is None:
            return None
        server_header = r.headers.get("Server", "")
        version_match = re.search(r"(\d+\.\d+(\.\d+)*)", server_header)
        if version_match:
            versions.append(version_match.group(1))

        soup = BeautifulSoup(r.text, "html.parser")
        meta = soup.find("meta", attrs={"name": "generator"})
        if meta:
            version_match = re.search(r"(\d+\.\d+(\.\d+)*)", meta.get("content", ""))
            if version_match:
                versions.append(version_match.group(1))

        if versions and len(set(versions)) == 1:
            return versions[0]
        else: return versions

        return None
        