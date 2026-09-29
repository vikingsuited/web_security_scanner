# Web Security Scanner

Passive and active external reconnaissance scanner written in Python. Assesses a web target's security posture including open ports, TLS/SSL configuration, HTTP security headers, and common exposed sensitive files.

Includes both a CLI tool, a Rich terminal interface, and a Flask web UI.

---

## Features

- **Port Scanning**: Multi-threaded check for common service ports (FTP, SSH, RDP, MySQL, Postgres, HTTP/S, etc.).
- **TLS Inspection**: Validates SSL/TLS certificate validity, issuer, expiration, and detects weak/legacy protocols (TLS 1.0/1.1).
- **Security Headers Check**: Audits missing headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, etc.) with explanation of risks.
- **Exposed Sensitive Paths**: Probes for sensitive endpoints (`/.git/config`, `/.env`, `/admin/`, `/phpinfo.php`, etc.).
- **SPA False-Positive Mitigation**: Uses baseline response comparison (differential testing) against catch-all client-side routes (e.g. React/Angular apps returning `200 OK` for every path) to filter out fake findings.
- **Risk Score Calculation**: Aggregates findings into a weighted score (0–100) with severity tiers (MINIMAL, LOW, MEDIUM, HIGH).

---

## Project Structure

```text
web_security_scanner/
├── web_scanner.py      # Core scanning logic & CLI implementation
├── app.py              # Flask backend server for Web UI
├── ui_scanner.py       # Rich terminal UI interface
├── templates/
│   └── index.html      # Single-page Web Dashboard
├── requirements.txt    # Project dependencies
├── render.yaml         # Cloud deployment configuration
└── README.md
