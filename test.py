import requests
import urllib3
from bs4 import BeautifulSoup
urllib3.disable_warnings()

s = requests.Session()
s.verify = False

import json
with open("orchestrator/config.json", encoding="utf-8") as f:
    config = json.load(f)

data={
    "username": "admin", 
    "password": "OJS_Scanner_1",  # ← ini
    "csrfToken": config.get("csrfToken", ""),
    "source": ""
}

# GET login
r = s.get("http://localhost:8081/coba/login")
print(f"OJSSID awal: {s.cookies.get('OJSSID')}")

csrf = BeautifulSoup(r.text, "html.parser").find("input", {"name": "csrfToken"})["value"]
print(f"CSRF: {csrf}")

# Tambah sebelum POST — lihat semua hidden fields di form login
soup = BeautifulSoup(r.text, "html.parser")
form = soup.find("form")
print(f"Form action: {form.get('action') if form else 'tidak ada'}")
print("Semua input fields:")
for inp in soup.find_all("input"):
    print(f"  name={inp.get('name')} type={inp.get('type')} value={inp.get('value', '')[:50]}")


# POST login
r2 = s.post(
    "http://localhost:8081/coba/login/signIn",
    data=data,
    allow_redirects=False
)
print(f"POST status: {r2.status_code}")
# Setelah POST berhasil 302
print(f"OJSSID setelah POST: {s.cookies.get('OJSSID')}")
print(f"Semua cookies: {s.cookies.get_dict()}")
ojssid = s.cookies.get("OJSSID")

s.cookies.clear()
jar = requests.cookies.RequestsCookieJar()
jar.set("OJSSID", ojssid)  # tanpa domain/path
s.cookies = jar

# Sebelum follow redirect, print request yang akan dikirim
req = requests.Request("GET", r2.headers.get("Location"))
prepared = s.prepare_request(req)
print(f"Headers yang akan dikirim: {prepared.headers}")
print(f"Cookies yang akan dikirim: {prepared.headers.get('Cookie')}")
print(f"Location: {r2.headers.get('Location')}")
req = requests.Request("GET", "http://localhost:8081/coba/submissions")
prepared = s.prepare_request(req)
print(f"Cookie sekarang: {prepared.headers.get('Cookie')}")
print(f"OJSSID setelah POST: {s.cookies.get('OJSSID')}")
print(f"POST response preview: {r2.text[:500]!r}")
soup2 = BeautifulSoup(r2.text, "html.parser")
error = soup2.find(class_="error") or soup2.find(class_="pkp_notification")
print(f"Error message: {error.text if error else 'tidak ada'}")

# Follow redirect
r3 = s.get("http://localhost:8081/coba/submissions")
print(f"Status: {r3.status_code}, URL: {r3.url}")
print(f"Login berhasil: {'pkp_page_login' not in r3.text}")

# Mimic scanner — loop beberapa request setelah login
print("\n--- Loop request setelah login ---")
test_urls = [
    "http://localhost:8081/coba/submissions",
    "http://localhost:8081/coba/manageIssues",
    "http://localhost:8081/coba/$$$call$$$/grid/issues/future-issue-grid/add-issue",
    "http://localhost:8081/coba/api/v1/users",
    "http://localhost:8081/coba/management/settings/context",
]

for url in test_urls:
    r = s.get(url)
    ojssid = s.cookies.get("OJSSID")
    is_login_page = "pkp_page_login" in r.text or "login" in r.url
    print(f"  {url}")
    print(f"    status={r.status_code} OJSSID={ojssid} login_page={is_login_page}")