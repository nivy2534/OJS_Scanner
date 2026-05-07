# External Scanner

Scanner keamanan untuk Open Journal Systems (OJS) yang melakukan crawling dan scanning vulnerability secara otomatis.

## Struktur Direktori

```
external/
├── main.py                  # Entry point standalone
├── crawler/                 # Modul crawling URL
│   ├── crawl.py             # Runner crawler standalone
│   ├── crawlers.py          # Implementasi crawler utama
│   └── pw_login.py          # Login berbasis Playwright
├── scanner/                 # Modul scanning vulnerability
│   ├── scanner.py           # Scanner utama
│   ├── matcher.py           # Pencocokan response terhadap rule
│   ├── payload_engine.py    # Engine injeksi payload
│   ├── rule_loader.py       # Loader file rule YAML
│   └── modules/
│       └── finger_print.py  # Deteksi versi server & OJS
├── rules/                   # Rule vulnerability dalam format YAML
│   ├── broken_auth.yaml     # Broken authentication
│   ├── idor.yaml            # Insecure Direct Object Reference
│   ├── rce.yaml             # Remote Code Execution
│   ├── xss.yaml             # Cross-Site Scripting (stored)
│   └── xxe.yaml             # XML External Entity
└── utils/
    └── session_manager.py   # Manajemen sesi & autentikasi
```

## Cara Kerja

### 1. Session Manager

`SessionManager` menangani autentikasi ke OJS dan menjaga sesi tetap valid selama scanning berlangsung. Sesi di-refresh otomatis ketika expired atau sebelum scan sensitif dijalankan.

```python
from utils.session_manager import SessionManager

sm = SessionManager(
    domain="http://localhost:8081",
    journal="coba",
    username="admin",
    password="password"
)
```

### 2. Crawler

Crawler melakukan dua hal: menjelajahi halaman OJS secara terautentikasi dan menemukan URL dinamis melalui API.

```python
from crawler.crawlers import Crawlers

crawler = Crawlers(domain="http://localhost:8081", journal="coba", sm=sm)
urls = crawler.crawl()
```

URL yang di-skip secara otomatis: `signOut`, `logout`, dan URL berbahaya lainnya yang bisa mengakhiri sesi.

### 3. Scanner

Scanner menerima daftar URL hasil crawl dan menjalankan rule-rule vulnerability.

```python
from scanner.scanner import Scanner

scanner = Scanner(session_manager=sm)
findings = scanner.run(
    endpoints=urls,
    base_url="http://localhost:8081",
    journal="coba"
)
```

### 4. Rule System

Rule ditulis dalam YAML dan mendukung empat tipe scan:

| Tipe | Deskripsi |
|------|-----------|
| `fuzz` | Fuzzing query parameter atau body |
| `probe` | Hit path langsung tanpa fuzzing |
| `idor` | Unauthenticated access & sequential ID enumeration |
| `form_xss` | XSS pada form yang dimuat via AJAX |

Contoh rule `form_xss`:

```yaml
id: xss-stored
name: stored XSS
severity: high
type: form_xss

ajax_patterns:
  - "add-issue"
  - "future-issue-grid"
  - "back-issue-grid"

requests:
  - method: POST
    fuzzing:
      - mode: replace
        params_pattern: "volume|number|year|title|description|urlPath"
        payloads:
          - "<script>alert(1)</script>"
          - "<img src=x onerror=alert(1)>"

matchers:
  - type: status
    status: [200]
  - type: word
    part: body
    condition: or
    words:
      - "<script>alert(1)</script>"
      - "onerror=alert(1)"
```

## Tipe Finding

Setiap finding mengandung field berikut:

```json
{
  "rule_id": "xss-stored",
  "rule_name": "stored XSS",
  "severity": "high",
  "url": "http://...",
  "param": "volume",
  "payload": "<script>alert(1)</script>",
  "status": 200,
  "verified": true,
  "test_type": "stored-xss"
}
```

Field `verified` bernilai `true` jika payload ditemukan di halaman yang merender data tersebut setelah POST. Field `test_type` bernilai `stored-xss` jika terverifikasi, atau `potential-stored-xss` jika belum.

## Catatan

- Scanner menggunakan `RequestsCookieJar` tanpa domain restriction untuk mengatasi masalah cookie di `localhost`.
- Session di-refresh otomatis sebelum rule `form_xss` dijalankan karena rule sebelumnya (terutama IDOR) dapat menyebabkan session invalidation.
- URL `signOut` dan `logout` di-skip otomatis oleh crawler untuk menjaga sesi tetap aktif.
- Semua file dibuka dengan `encoding='utf-8'` untuk menghindari error `charmap` di Windows.
