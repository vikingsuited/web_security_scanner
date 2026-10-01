# Web Security Scanner

Authorized testing only.

## Project structure
```
app.py                  Flask web UI + /api/scan + /health
web_scanner.py          Scan engine (modes, checks, scoring)
cli.py                  Optional terminal UI
requirements.txt        Runtime dependencies
render.yaml             Render deployment config
static/
├── css/style.css
└── js/main.js
templates/
└── index.html
```

## Run locally
```
pip install -r requirements.txt
python app.py             # http://127.0.0.1:5000
python cli.py             # interactive terminal scanner
python web_scanner.py example.com --mode deep --output report.json
```

## Scan modes
| Mode | Adds |
|---|---|
| light | Quick status, TLS certificate/protocol, essential security headers |
| medium | Light checks plus common ports/paths, all recommended headers, cookie flags, HTTPS redirect, robots.txt and security.txt checks |
| deep | Medium checks plus expanded port/path probes, legacy TLS, CORS and HTTP-method checks, fingerprinting, and same-origin crawl (up to 80 pages / 4 link levels) |

## Deploy on Render
1. Push this folder to a GitHub repo (files at repo root).
2. Render → New → Blueprint (uses render.yaml) or New Web Service:
   Build `pip install -r requirements.txt`, Start `gunicorn app:app --workers 2 --threads 4 --timeout 120`.
3. Env var `SCANNER_BLOCK_PRIVATE=1` stops visitors scanning internal IPs (already in render.yaml).
