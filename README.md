# Capstone OSINT Scanner

A web crawler and vulnerability scanner for OJS (Open Journal Systems) with authenticated session support.

## Requirements

- Python >= 3.12
- OJS instance (target)

## Installation

### Option 1 — Virtual Environment (Recommended)

A pre-configured virtual environment `.caps` is already included in the repository.

**Windows:**
```cmd
.caps\Scripts\pip install -r requirements.txt
.caps\Scripts\playwright install chromium
```

To activate the virtual environment:
```cmd
.caps\Scripts\activate
```

Then run normally:
```cmd
python main.py crawler
```

To deactivate:
```cmd
deactivate
```

---

### Option 2 — Without Virtual Environment (System Python)

Install directly to your system Python:
```cmd
pip install -r requirements.txt --break-system-packages
playwright install chromium
```

> **Note:** `--break-system-packages` is required on some systems (e.g. Linux with externally managed Python). On Windows you can omit it if it causes issues.

Then run:
```cmd
python main.py crawler
```

---

### Option 3 — Create Your Own Virtual Environment

```cmd
python -m venv myenv

# Windows
myenv\Scripts\activate

# Linux / macOS
source myenv/bin/activate

pip install -r requirements.txt
playwright install chromium
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP session and authenticated crawling |
| `beautifulsoup4` | HTML parsing |
| `lxml` | XML/HTML parser backend |
| `playwright` | Browser-based crawling (optional) |
| `urllib3` | HTTP utilities |

---

## Usage

### Crawler

Crawls the target OJS instance and maps all accessible endpoints (authenticated + public).

```cmd
python main.py crawler
```

Results are saved to `results/urls.txt`.

---

## Project Structure

```
capstone/
├── main.py                  # Entry point
├── orchestrator/            # Job orchestration and async runner
├── external/
│   ├── crawler/             # Crawler module (requests-based)
│   └── utils/               # Session manager, helpers
├── scanner/                 # Vulnerability scanner modules
│   ├── core/
│   └── modules/
├── results/                 # Output files
├── rules/                   # Scanner rules
├── .caps/                   # Pre-built virtual environment
└── requirements.txt
```

---

## Notes

- The crawler handles OJS authenticated sessions automatically — it logs in, maintains the session, and re-authenticates if the session expires.
- Admin endpoints (`/management/*`, `/stats/*`, `/submissions`, etc.) are probed directly since they do not appear in public HTML.
- Dynamic URLs (per-submission, per-issue, per-user) are discovered via the OJS REST API (`/api/v1/`).
- Playwright is optional and only needed if you use the browser-based crawling mode.
