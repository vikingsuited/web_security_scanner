#!/usr/bin/env python3
"""
Web Security Scanner - core engine
Authorized testing only (your own systems or with explicit permission).

Scan modes (see MODES):
  light     TLS + core security headers                      (~5 s)
  medium    + common ports + sensitive files                 (~10 s)
  broad     + more ports/files, cookies, redirects, legacy TLS (~20 s)
  extended  + CORS, HTTP methods, dir listing, fingerprinting  (~45 s)

CLI:  python3 web_scanner.py example.com --mode broad --output report.json
"""
import argparse, concurrent.futures as cf, hashlib, ipaddress, json, logging
import os, re, socket, ssl, sys, time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3, warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("scanner")

TIMEOUT = 4
PORT_TIMEOUT = 1.5
UA = {"User-Agent": "WebSecurityScanner/2.0 (authorized testing)"}

# ---------------------------------------------------------------- data
PORTS_CORE = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
              443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
PORTS_BROAD = {53: "DNS", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 445: "SMB", 465: "SMTPS",
               587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
               2049: "NFS", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
               27017: "MongoDB"}
PORTS_EXT = {69: "TFTP", 161: "SNMP", 389: "LDAP", 636: "LDAPS", 873: "rsync", 1883: "MQTT",
             2375: "Docker API", 2376: "Docker TLS", 3000: "Dev server", 5000: "Dev server",
             5601: "Kibana", 5672: "AMQP", 5984: "CouchDB", 6443: "Kubernetes API", 8000: "HTTP-Alt",
             8008: "HTTP-Alt", 8081: "HTTP-Alt", 8888: "HTTP-Alt", 9090: "Prometheus/Web",
             10250: "Kubelet", 15672: "RabbitMQ Mgmt"}
PORT_RISK = {21: "medium", 23: "high", 135: "medium", 139: "medium", 445: "high", 1433: "high",
             1521: "high", 2049: "medium", 3306: "high", 3389: "high", 5432: "high", 5900: "high",
             6379: "high", 9200: "high", 11211: "high", 27017: "high", 2375: "critical",
             10250: "high", 161: "medium", 69: "medium", 873: "medium", 1883: "medium",
             5601: "medium", 5984: "medium", 6443: "medium", 15672: "low"}

# (path, severity, content-regex validator or None)
PATHS_CORE = [
    ("/.git/config", "critical", r"\[core\]"), ("/.env", "critical", r"^[a-z0-9_]+\s*=", ),
    ("/.aws/credentials", "critical", r"aws_(access|secret)"), ("/backup.zip", "high", None),
    ("/config.php.bak", "high", None), ("/phpinfo.php", "medium", r"php version|phpinfo"),
    ("/server-status", "medium", r"apache server status"), ("/.DS_Store", "low", None),
    ("/wp-admin/", "low", None), ("/admin/", "low", None)]
PATHS_BROAD = [
    ("/.git/HEAD", "critical", r"^ref:"), ("/.htpasswd", "critical", r":\$|:\{SHA\}"),
    ("/id_rsa", "critical", r"private key"), ("/database.sql", "critical", None),
    ("/dump.sql", "critical", None), ("/backup.sql", "critical", None),
    ("/wp-config.php.bak", "critical", None), ("/.svn/entries", "high", None),
    ("/backup.tar.gz", "high", None), ("/site.zip", "high", None),
    ("/docker-compose.yml", "high", r"^services:"), ("/.npmrc", "high", r"_authtoken|registry"),
    ("/.bash_history", "high", None), ("/console", "high", r"console"),
    ("/actuator/env", "high", r"propertysources"), ("/.htaccess", "medium", r"rewrite|deny|allow"),
    ("/Dockerfile", "medium", r"^from\s"), ("/actuator", "medium", r'"_links"'),
    ("/phpmyadmin/", "medium", r"phpmyadmin"), ("/composer.json", "low", r'"require"'),
    ("/package.json", "low", r'"dependencies"'), ("/swagger-ui.html", "low", r"swagger")]
PATHS_EXT = [
    ("/.env.local", "critical", r"^[a-z0-9_]+\s*="), ("/.env.production", "critical", r"^[a-z0-9_]+\s*="),
    ("/.env.backup", "critical", r"^[a-z0-9_]+\s*="), ("/actuator/heapdump", "critical", None),
    ("/error.log", "high", None), ("/access.log", "high", None), ("/settings.py", "high", r"secret_key"),
    ("/storage/logs/laravel.log", "high", r"laravel|stack trace"), ("/elmah.axd", "high", r"elmah"),
    ("/trace.axd", "high", r"trace"), ("/info.php", "medium", r"php version|phpinfo"),
    ("/server-info", "medium", r"apache server information"), ("/web.config", "medium", r"<configuration"),
    ("/config.json", "medium", r"[{]"), ("/config.yml", "medium", r"^[a-z_]+:"),
    ("/.idea/workspace.xml", "medium", r"<project"), ("/logs/", "medium", None),
    ("/backup/", "medium", None), ("/jenkins/", "medium", r"jenkins"), ("/solr/", "medium", r"solr"),
    ("/_profiler/", "medium", r"symfony"), ("/wp-json/wp/v2/users", "medium", r'"slug"'),
    ("/.gitignore", "low", r"node_modules|\.env|\.log"), ("/.vscode/settings.json", "low", r"[{]"),
    ("/crossdomain.xml", "low", r"cross-domain-policy"), ("/old/", "low", None), ("/tmp/", "low", None),
    ("/test.php", "low", None)]

# header: (severity, tier, why, fix)
HEADER_RULES = {
    "Strict-Transport-Security": ("medium", "core", "Missing HSTS - browsers can be downgraded to plain HTTP (MITM risk)",
                                  "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "Content-Security-Policy": ("medium", "core", "Missing CSP - weaker protection against XSS/injection",
                                "Add a Content-Security-Policy that restricts script sources"),
    "X-Frame-Options": ("low", "core", "Missing X-Frame-Options - clickjacking possible",
                        "Add X-Frame-Options: DENY (or CSP frame-ancestors 'none')"),
    "X-Content-Type-Options": ("low", "core", "Missing X-Content-Type-Options - MIME sniffing possible",
                               "Add X-Content-Type-Options: nosniff"),
    "Referrer-Policy": ("low", "core", "Missing Referrer-Policy - URLs may leak via referrer",
                        "Add Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy": ("low", "extra", "Missing Permissions-Policy - browser features not restricted",
                           "Add Permissions-Policy: camera=(), microphone=(), geolocation=()"),
    "Cross-Origin-Opener-Policy": ("low", "extra", "Missing COOP - cross-window attacks not isolated",
                                   "Add Cross-Origin-Opener-Policy: same-origin"),
    "Cross-Origin-Resource-Policy": ("low", "ext", "Missing CORP - resources can be embedded cross-origin",
                                     "Add Cross-Origin-Resource-Policy: same-site"),
}

CATEGORIES = {"network": "Network & Ports", "tls": "Encryption / TLS", "headers": "Security Headers",
              "cookies": "Cookies", "exposure": "Exposed Files", "config": "Server Configuration",
              "disclosure": "Information Disclosure"}

MODES = {
    "light": {"label": "Light", "eta": "~5 s",
              "desc": "Quick health check: TLS certificate, core security headers, server banner.",
              "ports": {}, "paths": [], "level": 1,
              "cats": ["tls", "headers", "disclosure"]},
    "medium": {"label": "Medium", "eta": "~10 s",
               "desc": "Adds common port scan and sensitive-file probing (.env, .git, backups).",
               "ports": PORTS_CORE, "paths": PATHS_CORE, "level": 2,
               "cats": ["network", "tls", "headers", "exposure", "disclosure"]},
    "broad": {"label": "Broad", "eta": "~20 s",
              "desc": "More ports and files, plus cookie flags, HTTP-to-HTTPS redirect, legacy TLS, robots/security.txt.",
              "ports": {**PORTS_CORE, **PORTS_BROAD}, "paths": PATHS_CORE + PATHS_BROAD, "level": 3,
              "cats": ["network", "tls", "headers", "cookies", "exposure", "config", "disclosure"]},
    "extended": {"label": "Extended", "eta": "~45 s",
                 "desc": "Everything in Broad plus CORS, risky HTTP methods, directory listing, tech fingerprinting, largest port/file lists.",
                 "ports": {**PORTS_CORE, **PORTS_BROAD, **PORTS_EXT},
                 "paths": PATHS_CORE + PATHS_BROAD + PATHS_EXT, "level": 4,
                 "cats": ["network", "tls", "headers", "cookies", "exposure", "config", "disclosure"]},
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_WEIGHT = {"critical": 35, "high": 20, "medium": 10, "low": 4, "info": 0}


# ---------------------------------------------------------------- helpers
def normalize_target(target):
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    p = urlparse(target)
    if not p.hostname:
        raise ValueError("Invalid target")
    port = p.port or (443 if p.scheme == "https" else 80)
    return p.hostname, p.scheme, f"{p.scheme}://{p.netloc}", port


def guard_target(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {host}")
    if os.environ.get("SCANNER_BLOCK_PRIVATE") == "1":
        for info in infos:
            if not ipaddress.ip_address(info[4][0].split("%")[0]).is_global:
                raise ValueError("Scanning private/internal addresses is disabled on this server.")


def fetch(url, method="GET", headers=None, max_bytes=4096):
    r = requests.request(method, url, headers={**UA, **(headers or {})}, timeout=TIMEOUT,
                         allow_redirects=False, stream=True, verify=False)
    try:
        body = next(r.iter_content(max_bytes), b"")
    finally:
        r.close()
    return r, body


def _finding(cat, sev, title, detail="", fix=""):
    return {"category": cat, "severity": sev, "title": title, "detail": detail, "fix": fix}


# ---------------------------------------------------------------- checks
def scan_ports(host, ports):
    log.info(f"Scanning {len(ports)} ports on {host}")

    def one(item):
        port, name = item
        try:
            with socket.create_connection((host, port), timeout=PORT_TIMEOUT):
                return {"port": port, "service": name}
        except Exception:
            return None

    with cf.ThreadPoolExecutor(max_workers=48) as pool:
        found = [r for r in pool.map(one, ports.items()) if r]
    return sorted(found, key=lambda p: p["port"])


def check_tls(host, port):
    log.info(f"Checking TLS on {host}:{port}")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert, proto = s.getpeercert(), s.version()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (not_after - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {"reachable": True, "protocol": proto, "issuer": issuer.get("organizationName", "Unknown"),
                "expires": cert["notAfter"], "days_until_expiry": days, "expiring_soon": days < 30,
                "expired": days < 0, "weak_protocol": proto in ("TLSv1", "TLSv1.1", "SSLv3"),
                "san": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:10]}
    except ssl.SSLCertVerificationError as e:
        return {"reachable": True, "invalid_cert": True, "error": f"Certificate verification failed: {e.verify_message}"}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def probe_legacy_tls(host, port):
    weak = []
    for name, ver in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            ctx.minimum_version = ctx.maximum_version = ver
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=TIMEOUT) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    weak.append(name)
        except Exception:
            pass
    return weak


def analyze_headers(resp, level, f):
    h = resp.headers
    https = resp.url.startswith("https")
    csp = h.get("Content-Security-Policy", "")
    present = {}
    for name, (sev, tier, why, fix) in HEADER_RULES.items():
        if tier == "extra" and level < 3 or tier == "ext" and level < 4:
            continue
        if name == "Strict-Transport-Security" and not https:
            continue
        if name in h:
            present[name] = h[name]
        elif name == "X-Frame-Options" and "frame-ancestors" in csp.lower():
            present[name] = "(via CSP frame-ancestors)"
        else:
            f.append(_finding("headers", sev, name, why, fix))
    if level >= 3:
        m = re.search(r"max-age=(\d+)", h.get("Strict-Transport-Security", ""))
        if m and int(m.group(1)) < 15552000:
            f.append(_finding("headers", "low", "Weak HSTS max-age", f"max-age={m.group(1)} is under 180 days",
                              "Use max-age=31536000 or higher"))
        if re.search(r"unsafe-(inline|eval)", csp):
            f.append(_finding("headers", "low", "CSP allows unsafe-inline/unsafe-eval",
                              "Weakens XSS protection", "Use nonces or hashes instead of unsafe-inline"))
    for bh in ("Server", "X-Powered-By"):
        if bh in h:
            versioned = bh == "X-Powered-By" or bool(re.search(r"\d", h[bh]))
            f.append(_finding("disclosure", "low" if versioned else "info", f"{bh} header disclosed: {h[bh]}",
                              "Reveals server software" + (" and version" if versioned else ""),
                              f"Remove or genericize the {bh} header"))
    return present


def analyze_cookies(resp, https, f):
    try:
        cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        cookies = [resp.headers["Set-Cookie"]] if "Set-Cookie" in resp.headers else []
    for c in cookies:
        name, low = c.split("=")[0].strip(), c.lower()
        miss = [x for x, ok in (("Secure", "secure" in low or not https), ("HttpOnly", "httponly" in low),
                                ("SameSite", "samesite" in low)) if not ok]
        if miss:
            sev = "medium" if ("Secure" in miss or "HttpOnly" in miss) else "low"
            f.append(_finding("cookies", sev, f"Cookie '{name}' missing {', '.join(miss)}",
                              "Cookie flags protect against theft and CSRF",
                              "Set Secure; HttpOnly; SameSite=Lax (or Strict)"))
    return [c.split("=")[0].strip() for c in cookies]


def check_exposed_paths(base_url, entries):
    log.info(f"Probing {len(entries)} paths")
    sig = lambda u: _sig(u)
    baselines = {"file": sig(base_url + "/definitely-not-a-real-path-xyz123"),
                 "dir": sig(base_url + "/definitely-not-a-real-dir-xyz123/")}

    def probe(entry):
        path, sev, rx = entry
        try:
            r, body = fetch(base_url + path)
        except requests.RequestException:
            return None
        if r.status_code != 200:
            return None
        base = baselines["dir" if path.endswith("/") else "file"]
        digest = hashlib.md5(body).hexdigest()
        if base and base[0] == 200 and base[1] == digest:
            return None                      # SPA catch-all: same page for any URL
        if rx:
            if not re.search(rx, body.decode("utf-8", "ignore"), re.M | re.I):
                return None
        elif base and base[0] == 200 and "text/html" in r.headers.get("Content-Type", ""):
            return None                      # HTML served for a non-HTML resource
        return {"path": path, "severity": sev, "status_code": 200}

    with cf.ThreadPoolExecutor(max_workers=12) as pool:
        return sorted([r for r in pool.map(probe, entries) if r], key=lambda e: SEV_ORDER[e["severity"]])


def _sig(url):
    try:
        r, body = fetch(url)
        return r.status_code, hashlib.md5(body).hexdigest()
    except requests.RequestException:
        return None


def check_http_redirect(host, scheme, f):
    if scheme != "https":
        return
    try:
        r, _ = fetch(f"http://{host}")
        loc = r.headers.get("Location", "")
        if not (r.status_code in (301, 302, 307, 308) and loc.startswith("https://")):
            f.append(_finding("config", "medium", "No HTTP to HTTPS redirect",
                              f"http://{host} answered {r.status_code} without redirecting to HTTPS",
                              "Redirect all HTTP traffic to HTTPS"))
    except requests.RequestException:
        pass


def check_meta(base_url, f):
    try:
        r, body = fetch(base_url + "/robots.txt")
        txt = body.decode("utf-8", "ignore")
        dis = re.findall(r"^disallow:\s*(\S+)", txt, re.I | re.M)
        if r.status_code == 200 and "text/html" not in r.headers.get("Content-Type", "") and dis:
            f.append(_finding("disclosure", "info", f"robots.txt lists {len(dis)} disallowed paths",
                              "Examples: " + ", ".join(dis[:5]), "Do not rely on robots.txt to hide sensitive paths"))
    except requests.RequestException:
        pass
    try:
        r, body = fetch(base_url + "/.well-known/security.txt")
        if not (r.status_code == 200 and re.search(r"^contact:", body.decode("utf-8", "ignore"), re.I | re.M)):
            f.append(_finding("config", "info", "No security.txt", "No vulnerability-disclosure contact published",
                              "Publish /.well-known/security.txt (RFC 9116)"))
    except requests.RequestException:
        pass


def check_extended(base_url, home, cookie_names, f):
    try:  # CORS
        r, _ = fetch(base_url, headers={"Origin": "https://evil.example"})
        acao = r.headers.get("Access-Control-Allow-Origin")
        cred = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == "https://evil.example":
            f.append(_finding("config", "high" if cred else "medium", "CORS reflects arbitrary Origin",
                              "Any website can read responses" + (" with credentials" if cred else ""),
                              "Allow-list trusted origins only"))
        elif acao == "*":
            f.append(_finding("config", "low", "CORS allows any origin (*)", "", "Restrict to trusted origins"))
    except requests.RequestException:
        pass
    try:  # TRACE / OPTIONS
        r, body = fetch(base_url, method="TRACE")
        if r.status_code == 200 and b"TRACE" in body:
            f.append(_finding("config", "medium", "HTTP TRACE enabled", "Can aid cross-site tracing attacks",
                              "Disable the TRACE method"))
        r, _ = fetch(base_url, method="OPTIONS")
        risky = [m for m in ("PUT", "DELETE", "PATCH") if m in r.headers.get("Allow", "").upper()]
        if risky:
            f.append(_finding("config", "low", f"Risky methods advertised: {', '.join(risky)}", "",
                              "Restrict allowed methods to those the app needs"))
    except requests.RequestException:
        pass
    if home is not None and re.search(r"<title>index of /|<h1>index of /", home, re.I):
        f.append(_finding("config", "medium", "Directory listing enabled", "Home page shows a file index",
                          "Disable autoindex/directory listing"))
    tech = {"PHPSESSID": "PHP", "JSESSIONID": "Java", "ASP.NET_SessionId": "ASP.NET",
            "laravel_session": "Laravel", "connect.sid": "Node/Express"}
    found = {tech[c] for c in cookie_names if c in tech}
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', home or "", re.I)
    if m:
        found.add(m.group(1))
    if found:
        f.append(_finding("disclosure", "info", "Technology fingerprint: " + ", ".join(sorted(found)),
                          "Helps attackers target known vulnerabilities", "Hide generator tags and default cookie names"))


# ---------------------------------------------------------------- scoring / main
def calculate_risk_score(findings):
    return min(sum(SEV_WEIGHT[x["severity"]] for x in findings), 100)


def risk_label(score):
    return "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW" if score > 0 else "MINIMAL"


def run_scan(target, mode="medium"):
    mode = mode if mode in MODES else "medium"
    cfg, level = MODES[mode], MODES[mode]["level"]
    host, scheme, base_url, port = normalize_target(target)
    guard_target(host)
    log.info(f"=== {mode.upper()} scan of {base_url} ===")
    t0, f = time.time(), []

    with cf.ThreadPoolExecutor(max_workers=4) as pool:      # slow, independent checks run in parallel
        ports_f = pool.submit(scan_ports, host, cfg["ports"]) if cfg["ports"] else None
        paths_f = pool.submit(check_exposed_paths, base_url, cfg["paths"]) if cfg["paths"] else None
        tls_f = pool.submit(check_tls, host, port) if scheme == "https" else None
        legacy_f = pool.submit(probe_legacy_tls, host, port) if scheme == "https" and level >= 3 else None
        try:
            home = requests.get(base_url, headers=UA, timeout=TIMEOUT, allow_redirects=True, verify=False)
            home_err = None
        except requests.RequestException as e:
            home, home_err = None, str(e)

        open_ports = ports_f.result() if ports_f else []
        exposed = paths_f.result() if paths_f else []
        tls = tls_f.result() if tls_f else {"reachable": False, "error": "Target uses plain HTTP"}
        legacy = legacy_f.result() if legacy_f else []

    # network
    for p in open_ports:
        sev = PORT_RISK.get(p["port"], "info")
        f.append(_finding("network", sev, f"Port {p['port']}/{p['service']} open",
                          "Externally reachable service", "Firewall or close it if not required" if sev != "info" else ""))
    # tls
    if scheme != "https":
        f.append(_finding("tls", "high", "Site served over plain HTTP", "No encryption in transit", "Enable HTTPS"))
    elif not tls.get("reachable"):
        f.append(_finding("tls", "medium", "TLS not reachable", tls.get("error", ""), "Check HTTPS on the port"))
    else:
        if tls.get("invalid_cert"):
            f.append(_finding("tls", "high", "Invalid or untrusted certificate", tls["error"], "Install a valid certificate"))
        if tls.get("expired"):
            f.append(_finding("tls", "critical", "Certificate expired", "", "Renew immediately"))
        elif tls.get("expiring_soon"):
            f.append(_finding("tls", "medium", f"Certificate expires in {tls['days_until_expiry']} days", "", "Renew soon"))
        if tls.get("weak_protocol"):
            f.append(_finding("tls", "high", f"Negotiated outdated protocol {tls['protocol']}", "", "Require TLS 1.2+"))
    for v in legacy:
        f.append(_finding("tls", "medium", f"Legacy protocol {v} accepted", "Deprecated and weak", "Disable TLS 1.0/1.1"))
    # http layer
    headers, cookie_names = {"missing": [], "present": {}, "server_banner": None}, []
    if home is not None:
        headers["present"] = analyze_headers(home, level, f)
        headers["status_code"] = home.status_code
        if level >= 3:
            cookie_names = analyze_cookies(home, home.url.startswith("https"), f)
    else:
        headers["error"] = home_err
    # exposure
    for e in exposed:
        f.append(_finding("exposure", e["severity"], f"Exposed: {e['path']}", "Publicly reachable (HTTP 200)",
                          "Remove from web root or block in server config"))
    if level >= 3:
        check_http_redirect(host, scheme, f)
        check_meta(base_url, f)
    if level >= 4:
        check_extended(base_url, home.text[:20000] if home is not None else None, cookie_names, f)

    f.sort(key=lambda x: SEV_ORDER[x["severity"]])
    headers["missing"] = [{"header": x["title"], "risk": x["detail"]} for x in f if x["category"] == "headers" and x["title"] in HEADER_RULES]
    score = calculate_risk_score(f)
    summary = {s: sum(1 for x in f if x["severity"] == s) for s in SEV_ORDER}
    cats = [{"id": c, "name": CATEGORIES[c], "count": sum(1 for x in f if x["category"] == c)} for c in cfg["cats"]]
    return {"target": base_url, "host": host, "mode": mode, "mode_label": cfg["label"],
            "scanned_at": datetime.now(timezone.utc).isoformat(), "duration_s": round(time.time() - t0, 1),
            "findings": f, "categories": cats, "summary": summary, "open_ports": open_ports, "tls": tls,
            "headers": headers, "exposed_paths": exposed, "risk_score": score, "risk_label": risk_label(score)}


def print_report(r):
    print(f"\n{'=' * 64}\n {r['mode_label'].upper()} SCAN: {r['target']}  ({r['duration_s']}s)\n{'=' * 64}")
    print(f"Risk {r['risk_score']}/100 [{r['risk_label']}]  " + "  ".join(f"{k}:{v}" for k, v in r["summary"].items() if v))
    for c in r["categories"]:
        print(f"\n## {c['name']} ({c['count']})")
        for x in (x for x in r["findings"] if x["category"] == c["id"]):
            print(f"  [{x['severity'].upper():8}] {x['title']}" + (f" - {x['fix']}" if x["fix"] else ""))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Web security scanner")
    ap.add_argument("target")
    ap.add_argument("--mode", choices=list(MODES), default="medium")
    ap.add_argument("--output", help="write JSON report")
    a = ap.parse_args()
    print("Authorized-testing use only.\n")
    res = run_scan(a.target, a.mode)
    print_report(res)
    if a.output:
        json.dump(res, open(a.output, "w"), indent=2)
