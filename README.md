# Web Security Scanner

Authorized testing only.

## Folder structure (keep exactly like this)
```
web_scanner/
├── app.py              Flask web UI + /api/scan + /health
├── web_scanner.py      scan engine (modes, checks, scoring)
├── ui_scanner.py       optional terminal UI
├── requirements.txt
├── render.yaml         Render deploy config
├── .gitignore
└── templates/
    └── index.html      MUST be inside templates/
```

## Run locally
```
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
python web_scanner.py example.com --mode broad --output report.json
```

## Scan modes
| Mode | Adds |
|---|---|
| light | TLS, core headers, banner |
| medium | + 13 ports, 10 sensitive files |
| broad | + 30 ports, 32 files, cookies, HTTP→HTTPS, legacy TLS, robots/security.txt |
| extended | + 53 ports, 59 files, CORS, TRACE/OPTIONS, dir listing, fingerprinting |

## Deploy on Render
1. Push this folder to a GitHub repo (files at repo root).
2. Render → New → Blueprint (uses render.yaml) or New Web Service:
   Build `pip install -r requirements.txt`, Start `gunicorn app:app --workers 2 --threads 4 --timeout 120`.
3. Env var `SCANNER_BLOCK_PRIVATE=1` stops visitors scanning internal IPs (already in render.yaml).
