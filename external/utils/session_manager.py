import threading
import time
import os
import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from requests.cookies import RequestsCookieJar
import http.cookiejar

class SessionManager:

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self, domain=None, journal=None, username=None, password=None, persist_path=None):
        if not self._initialized:
            self.domain = domain.rstrip("/") if domain else None
            self.journal = journal
            self.username = username
            self.password = password
            self.persist_path = persist_path

            # ✅ Gunakan _session dan _csrf_token sebagai backing variable
            self._session = None
            self._csrf_token = None
            self._session_expiry = None
            self.session_lock = threading.Lock()
            self.SESSION_TTL = 3600
            self._auto_refresh_enabled = True

            self._initialized = True

            if persist_path and os.path.exists(persist_path):
                self._load_from_file()
            else:
                self._create_session()

    @property
    def session(self) -> requests.Session:
        # ✅ Tidak perlu lock di sini karena _create_session sudah lock
        if self._is_expired():
            print("[SessionManager] Session expired, creating new session...")
            self._create_session()
        return self._session

    @property
    def csrf_token(self) -> str:
        # ✅ Property untuk csrf_token
        if not self._csrf_token or self._is_expired():
            print("[SessionManager] CSRF token expired, creating new session...")
            self._create_session()
        return self._csrf_token

    def force_refresh(self):
        print("[SessionManager] Force refreshing session...")
        self._create_session()

    def get(self, url, **kwargs) -> requests.Response:
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs) -> requests.Response:
        return self._request("POST", url, **kwargs)

    def _request(self, method, url, _retry=True, **kwargs) -> requests.Response:
        kwargs.setdefault("verify", False)
        kwargs.setdefault("timeout", 10)

        r = self._session.request(method, url, **kwargs)

        if _retry and self._auto_refresh_enabled and self._detect_session_expiry(r):
            print(f"[SessionManager] Detected session expiry on {url}, refreshing...")
            self.force_refresh()
            return self._request(method, url, _retry=False, **kwargs)

        return r  # ✅ Selalu return

    def _detect_session_expiry(self, response: requests.Response) -> bool:
        original_path = urlparse(response.request.url).path.lower()
        final_path = urlparse(response.url).path.lower()

        if response.status_code == 403 and "/api/" in original_path:
            return False
        if response.status_code == 401:
            return True

        if "login" in original_path:
            return False
        
        if "login" in final_path and "login" not in original_path:
            return True

        public_hints = ["/about", "/search", "/issue", "/register", "/index"]
        is_public = any(hint in original_path for hint in public_hints)
        if not is_public and "pkp_page_login" in response.text:
            return True
        return False

    def _is_expired(self) -> bool:
        # ✅ Nama konsisten, handle None
        if self._session_expiry is None:
            return True
        return time.time() > self._session_expiry

    def _create_session(self):
        # ✅ Nama konsisten (private), dengan lock
        with self.session_lock:
            self._session = self._build_session()
            success = self._login()

            if success:
                self._session_expiry = time.time() + self.SESSION_TTL
                print(f"[SessionManager] Session created, expires in {self.SESSION_TTL}s")
                if self.persist_path:
                    self._save_to_file()
            else:
                raise RuntimeError("[SessionManager] Failed to create session")

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/146.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "sec-ch-ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Upgrade-Insecure-Requests": "1",
        })
        return s

    def _login(self) -> bool:
        base_url = f"{self.domain}/{self.journal}/"
        login_url = f"{base_url}login"

        try:
            # ✅ GET login page — server set OJSSID awal di sini
            r = self._session.get(login_url, verify=False, timeout=10)
            
            print(f"[DEBUG] Cookies setelah GET login: {[(c.name, c.value[:10], c.domain) for c in self._session.cookies]}")
            
            soup = BeautifulSoup(r.text, "html.parser")
            csrf_input = soup.find("input", {"name": "csrfToken"})
            if not csrf_input:
                print("[!] CSRF Token tidak ditemukan")
                return False

            self._csrf_token = csrf_input.get("value")

            self._session.headers.update({
                "Referer": login_url,
                "Sec-Fetch-Site": "same-origin",
            })

            # ✅ Inject cookie OJSSID yang ada ke header secara eksplisit untuk POST
            ojssid_before = next((c.value for c in self._session.cookies if c.name == "OJSSID"), None)
            if ojssid_before:
                self._session.headers.update({"Cookie": f"OJSSID={ojssid_before}"})
            
            print(f"[DEBUG] OJSSID sebelum POST: {ojssid_before}")
            print(f"[DEBUG] CSRF token: {self._csrf_token}")

            r = self._session.post(
                f"{base_url}login/signIn",
                data={
                    "username":  self.username,
                    "password":  self.password,
                    "csrfToken": self._csrf_token,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                verify=False,
                timeout=10,
                allow_redirects=False
            )

            print(f"[DEBUG] POST status: {r.status_code}, Location: {r.headers.get('Location', '-')}")
            print(f"[DEBUG] Set-Cookie dari POST: {r.headers.get('Set-Cookie', '-')}")

            location = r.headers.get("Location", "")
            if r.status_code != 302 or "login" in location:
                print(f"[!] Login gagal — Location: {location}")
                return False

            # ✅ Ambil OJSSID baru dari response POST
            ojssid_new = None
            for h in r.headers.get("Set-Cookie", "").split(";"):
                if "OJSSID=" in h:
                    ojssid_new = h.strip().split("=")[1]
                    break

            if not ojssid_new:
                # fallback dari jar
                ojssid_new = next((c.value for c in self._session.cookies if c.name == "OJSSID"), None)

            if not ojssid_new:
                print("[!] OJSSID tidak ditemukan setelah login")
                return False

            # ✅ Update header Cookie ke OJSSID baru
            self._session.headers.update({"Cookie": f"OJSSID={ojssid_new}"})
            self._ojssid = ojssid_new

            # ✅ Follow redirect untuk establish session
            r_redirect = self._session.get(urljoin(self.domain, location), verify=False, timeout=10)
            print(f"[DEBUG] Redirect final URL: {r_redirect.url}")
            print(f"[DEBUG] Redirect pkp_login: {'pkp_page_login' in r_redirect.text}")

            if "pkp_page_login" in r_redirect.text:
                print("[!] Session tidak valid setelah redirect")
                return False

            print(f"[SessionManager] Login successful, OJSSID: {ojssid_new}")
            return True

        except Exception as e:
            print(f"[SessionManager] Error during login: {e}")
            return False
        
    def _save_to_file(self):
        """Simpan cookie + expiry ke file (opsional)."""
        data = {
            "cookies": {
                c.name: c.value
                for c in self._session.cookies
            },
            "csrf_token": self._csrf_token,
            "expiry":     self._session_expiry,
        }
        with open(self.persist_path, "w") as f:
            json.dump(data, f)
        print(f"[*] Session disimpan ke {self.persist_path}")

    def _load_from_file(self):
        """Load session dari file cache."""
        try:
            with open(self.persist_path) as f:
                data = json.load(f)

            # Cek apakah masih valid
            if time.time() > data.get("expiry", 0):
                print("[*] Cache expired — login ulang...")
                self._create_session()
                return

            self._session      = self._build_session()
            self._csrf_token   = data.get("csrf_token")
            self._session_expiry = data["expiry"]

            parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(self.domain)
            for name, value in data["cookies"].items():
                self._session.cookies.set(
                    name, value,
                    domain=parsed.netloc.split(":")[0],
                    path="/"
                )
            print(f"[*] Session di-load dari {self.persist_path}")

        except Exception as e:
            print(f"[!] Gagal load session cache: {e} — login ulang...")
            self._create_fresh_session()