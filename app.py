#!/usr/bin/env python3
"""Web Security Scanner - Flask UI. Local: python3 app.py   Cloud: gunicorn app:app"""
import os, time
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request

from web_scanner import MODES, run_scan

# Templates qovluğunun dəqiq yolunu təyin edirik
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

app = Flask(__name__, template_folder=TEMPLATE_DIR)

HITS = defaultdict(deque)
RATE_LIMIT, WINDOW = 6, 60          # scans per IP per minute


def rate_limited():
    ip = (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()
    q, now = HITS[ip], time.time()
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


def do_scan(target, mode):
    if not target or len(target) > 253:
        raise ValueError("Please enter a valid target URL or hostname.")
    if rate_limited():
        raise ValueError("Too many scans - wait a minute and try again.")
    return run_scan(target, mode if mode in MODES else "medium")


@app.route("/", methods=["GET", "POST"])
def index():
    results = error = None
    target, mode = "", "medium"
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        mode = request.form.get("mode", "medium")
        if not request.form.get("authorized"):
            error = "Please confirm you are authorized to test this target."
        else:
            try:
                results = do_scan(target, mode)
            except ValueError as e:
                error = str(e)
            except Exception as e:
                error = f"Scan failed: {e}"
    return render_template("index.html", results=results, error=error, target=target, mode=mode, modes=MODES)


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    if not data.get("authorized"):
        return jsonify(error="Set 'authorized': true to confirm you may test this target."), 400
    try:
        return jsonify(do_scan(str(data.get("target", "")).strip(), data.get("mode", "medium")))
    except ValueError as e:
        return jsonify(error=str(e)), 400


@app.get("/health")
def health():
    return "ok"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"Starting at http://{host}:{port}  (Ctrl+C to stop)")
    app.run(host=host, port=port, debug=False)
