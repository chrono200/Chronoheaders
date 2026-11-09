#!/usr/bin/env python3
"""
ChronoHeaders - HTTP security header grader.
Grades security headers and cookies, checks CORS and HTTPS enforcement,
generates fix snippets and detects regressions between scans.
Part of the CHRONO SUITE.
Dev: Chrono

For legal, defensive and educational use on sites you own or are
authorized to test.
"""

import argparse
import concurrent.futures
import datetime as dt
import http.client
import json
import re
import socket
import ssl
import sys
import urllib.parse
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

VERSION = "1.0.0"
DEV = "Chrono"
DISCLAIMER = "For legal, defensive and educational use on sites you own or are authorized to test."
UA = f"ChronoHeaders/{VERSION}"
SUBCOMMANDS = ("scan", "raw", "fix")
GRADES = ["F", "D", "C", "B", "A", "A+"]
STATUS_COLOR = {"PASS": "green", "WARN": "yellow", "FAIL": "red", "INFO": "cyan"}
GRADE_COLOR = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}
REDIRECTS = (301, 302, 303, 307, 308)
EVIL_ORIGIN = "https://chronoheaders-test.invalid"
FORMATS = ("nginx", "apache", "caddy", "express")

HSTS_REC = "max-age=31536000; includeSubDomains"
CSP_REC = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
REC = {
    "Strict-Transport-Security": HSTS_REC,
    "Content-Security-Policy": CSP_REC,
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
TRACKED = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
           "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
           "cross-origin-resource-policy", "cross-origin-embedder-policy"]

console = Console()
err_console = Console(stderr=True)

# ------------------------------------------------------------- banner ----

STOPS = [(122, 92, 255), (58, 123, 255), (0, 180, 216), (46, 229, 157), (155, 224, 0), (255, 176, 0)]

# Logo: a shield with a check mark (this tool's mascot).
LOGO = [
    r" .--------------------------------. ",
    r" |  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  | ",
    r" |  ~~~~~~~~~~~~~~~~~~~~          | ",
    r" |  ~~~~~~~~~~~~~~~~~~~~~~~~      | ",
    r" |                                | ",
    r" |                      /         | ",
    r" |                     /          | ",
    r" |                    /           | ",
    r" |             \     /            | ",
    r" |              \   /             | ",
    r" |               \ /              | ",
    r" |                V               | ",
    r" |                                | ",
    r"  \                              /  ",
    r"   \                            /   ",
    r"    '.                        .'    ",
    r"      '-.                  .-'      ",
    r"         '-.            .-'         ",
    r"            '-..____..-'            ",
]
NAME_TOP = [
    r"  _____   _                                     ",
    r" / ____| | |                                    ",
    r"| |      | |__    _ __    ___    _ __     ___   ",
    r"| |      | '_ \  | '__|  / _ \  | '_ \   / _ \  ",
    r"| |____  | | | | | |    | (_) | | | | | | (_) | ",
    r" \_____| |_| |_| |_|     \___/  |_| |_|  \___/  ",
]
NAME_BOTTOM = [
    r" _    _                      _                      ",
    r"| |  | |                    | |                     ",
    r"| |__| |   ___    __ _    __| |   ___   _ __   ___  ",
    r"|  __  |  / _ \  / _` |  / _` |  / _ \ | '__| / __| ",
    r"| |  | | |  __/ | (_| | | (_| | |  __/ | |    \__ \ ",
    r"|_|  |_|  \___|  \__,_|  \__,_|  \___| |_|    |___/ ",
]


def _grad(t):
    t = max(0.0, min(1.0, t))
    x = t * (len(STOPS) - 1)
    i = min(int(x), len(STOPS) - 2)
    f = x - i
    a, b = STOPS[i], STOPS[i + 1]
    return "#%02x%02x%02x" % tuple(round(a[k] + (b[k] - a[k]) * f) for k in range(3))


def _centered(msg, style):
    console.print(Text(" " * max(0, (console.width - len(msg)) // 2) + msg, style=style))


def show_banner():
    blocks = [LOGO, [""], NAME_TOP, NAME_BOTTOM]
    width = max(len(l) for b in blocks for l in b)
    if console.width < width + 2:
        console.print(Text(f"CHRONOHEADERS // HTTP security header grader // Dev: {DEV}", style="bold #00b4d8"))
        return
    total = sum(len(b) for b in blocks)
    margin = (console.width - width) // 2
    text = Text()
    r = 0
    for block in blocks:
        lead = (width - max(len(l) for l in block)) // 2 + margin
        for line in block:
            text.append(" " * lead)
            for c, ch in enumerate(line):
                if ch == " ":
                    text.append(ch)
                else:
                    t = 0.88 * r / max(total - 1, 1) + 0.12 * (c + lead - margin) / width
                    text.append(ch, style=f"bold {_grad(t)}")
            text.append("\n")
            r += 1
    console.print(text, end="")
    console.print()
    _centered(f"HTTP security header grader  //  CHRONO SUITE v{VERSION}", "bold white")
    _centered(f"[ Dev: {DEV} ]", "bold #ffb000")
    _centered("scan  |  raw  |  fix", "#00b4d8")
    console.print()
    console.print(Text(DISCLAIMER, style="dim"))


# ------------------------------------------------------------ fetching ----

def normalize_url(raw):
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"invalid URL: {raw!r}")
    parts.port  # noqa: B018 - raises ValueError for a bad port
    return raw


def load_urls(urls, file):
    """De-duplicated list of (raw_text, normalized_url or None)."""
    raw = list(urls)
    if file:
        with open(file, encoding="utf-8") as fh:
            raw += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    seen, items = set(), []
    for item in raw:
        try:
            url = normalize_url(item)
        except ValueError:
            url = None
        if (url or item) not in seen:
            seen.add(url or item)
            items.append((item, url))
    return items


def fetch(url, timeout=10.0, verify=True, follow=True, max_redirects=5, extra_headers=None, user_agent=UA):
    """GET a URL, following redirects. Never raises: failures land in result['error']."""
    result = {"url": url, "final_url": url, "status": None, "headers": [], "chain": [], "error": None}
    headers = {"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
               "Accept-Encoding": "identity", "Connection": "close"}
    headers.update(extra_headers or {})
    current = url
    try:
        for _ in range(max_redirects + 1):
            parts = urllib.parse.urlsplit(current)
            https = parts.scheme == "https"
            port = parts.port or (443 if https else 80)
            if https:
                ctx = ssl.create_default_context()
                if not verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(parts.hostname, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            try:
                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()
                pairs, status = resp.getheaders(), resp.status
            finally:
                conn.close()
            result["chain"].append({"url": current, "status": status})
            result.update(final_url=current, status=status, headers=pairs)
            location = next((v for k, v in pairs if k.lower() == "location"), None)
            if follow and status in REDIRECTS and location:
                current = urllib.parse.urljoin(current, location)
                continue
            break
        else:
            result["error"] = f"more than {max_redirects} redirects"
    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"certificate not trusted: {exc.verify_message or exc} (use -k to ignore)"
    except socket.gaierror:
        result["error"] = "DNS lookup failed"
    except (socket.timeout, TimeoutError):
        result["error"] = f"timed out after {timeout:g}s"
    except ConnectionRefusedError:
        result["error"] = "connection refused"
    except ssl.SSLError as exc:
        result["error"] = f"TLS error: {exc.reason or exc}"
    except (http.client.HTTPException, OSError, ValueError) as exc:
        result["error"] = str(exc) or type(exc).__name__
    return result


def parse_raw(text):
    """Headers from `curl -I` / DevTools text. With several response blocks, the last one wins."""
    blocks = [b for b in re.split(r"\r?\n\s*\r?\n", text.strip()) if b.strip()]
    http_blocks = [b for b in blocks if b.lstrip().upper().startswith("HTTP/")]
    block = (http_blocks or blocks or [""])[-1]
    pairs, status = [], None
    for line in block.splitlines():
        line = line.strip()
        if line.upper().startswith("HTTP/"):
            m = re.match(r"HTTP/\S+\s+(\d{3})", line, re.I)
            status = int(m.group(1)) if m else None
        elif ":" in line:
            name, _, value = line.partition(":")
            if name.strip():
                pairs.append((name.strip(), value.strip()))
    return pairs, status


# ------------------------------------------------------------- checks ----

def hmap(pairs):
    out = {}
    for k, v in pairs:
        out.setdefault(k.lower(), []).append(v.strip())
    return out


def hget(h, name):
    vals = h.get(name)
    return ", ".join(vals) if vals else None


def chk(cid, name, status, earned, maximum, value=None, note="", fix=None):
    return {"id": cid, "name": name, "status": status, "earned": earned, "max": maximum,
            "value": value, "note": note, "fix": fix or []}


def check_hsts(h, https):
    v = hget(h, "strict-transport-security")
    name = "Strict-Transport-Security"
    fix = [("set", name, HSTS_REC)]
    if not https:
        return chk("hsts", name, "FAIL", 0, 20, v, "page is served over plain HTTP; HSTS only works on HTTPS")
    if not v:
        return chk("hsts", name, "FAIL", 0, 20, None, "missing", fix)
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age == 0:
        return chk("hsts", name, "FAIL", 0, 20, v, "max-age is 0 or missing, so HSTS is off", fix)
    low = v.lower()
    pts, notes = (14 if age >= 15552000 else 8), []
    if age < 15552000:
        notes.append("max-age under 180 days")
    if "includesubdomains" in low:
        pts += 3
    else:
        notes.append("no includeSubDomains")
    if "preload" in low and age >= 31536000 and "includesubdomains" in low:
        pts += 3
    elif "preload" in low:
        notes.append("preload needs max-age of 1 year and includeSubDomains")
    return chk("hsts", name, "PASS" if pts >= 17 else "WARN", pts, 20, v, "; ".join(notes),
               fix if pts < 17 else None)


def parse_csp(value):
    out = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if toks:
            out.setdefault(toks[0].lower(), toks[1:])
    return out


def check_csp(h):
    name = "Content-Security-Policy"
    enforced, report_only = hget(h, "content-security-policy"), hget(h, "content-security-policy-report-only")
    fix = [("set", name, CSP_REC)]
    if not enforced:
        if report_only:
            return chk("csp", name, "WARN", 5, 25, None, "only Report-Only is set, nothing is enforced", fix)
        return chk("csp", name, "FAIL", 0, 25, None, "missing", fix)
    d, pts, notes = parse_csp(enforced), 25, []
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        pts -= 8
        notes.append("no script-src or default-src")
    else:
        toks = [t.lower() for t in script]
        protected = any(t.startswith(("'nonce-", "'sha")) or t == "'strict-dynamic'" for t in toks)
        if "'unsafe-inline'" in toks and not protected:
            pts -= 8
            notes.append("script-src allows 'unsafe-inline'")
        if "'unsafe-eval'" in toks:
            pts -= 5
            notes.append("script-src allows 'unsafe-eval'")
        if "*" in toks or any(t in ("https:", "http:", "data:") for t in toks):
            pts -= 6
            notes.append("script-src allows any host or scheme")
    if "object-src" not in d and "default-src" not in d:
        pts -= 2
        notes.append("no object-src")
    if "base-uri" not in d:
        pts -= 2
        notes.append("no base-uri")
    if "frame-ancestors" not in d and not hget(h, "x-frame-options"):
        pts -= 2
        notes.append("no frame-ancestors")
    pts = max(pts, 5)
    status = "PASS" if not notes else "WARN" if pts >= 14 else "FAIL"
    return chk("csp", name, status, pts, 25, enforced, "; ".join(notes))


def check_frame(h):
    name = "Clickjacking (X-Frame-Options / frame-ancestors)"
    xfo, csp = hget(h, "x-frame-options"), hget(h, "content-security-policy")
    ancestors = parse_csp(csp).get("frame-ancestors") if csp else None
    if ancestors is not None:
        if "*" in ancestors:
            return chk("frame", name, "WARN", 4, 10, csp, "frame-ancestors allows any site")
        return chk("frame", name, "PASS", 10, 10, "frame-ancestors " + " ".join(ancestors))
    fix = [("set", "X-Frame-Options", REC["X-Frame-Options"])]
    if xfo:
        v = xfo.strip().upper()
        if v in ("DENY", "SAMEORIGIN"):
            return chk("frame", name, "PASS", 10, 10, xfo)
        if v.startswith("ALLOW-FROM"):
            return chk("frame", name, "WARN", 5, 10, xfo, "ALLOW-FROM is obsolete; use CSP frame-ancestors", fix)
        return chk("frame", name, "WARN", 3, 10, xfo, "unrecognised value", fix)
    return chk("frame", name, "FAIL", 0, 10, None, "missing: pages can be framed by any site", fix)


def check_xcto(h):
    name, v = "X-Content-Type-Options", hget(h, "x-content-type-options")
    fix = [("set", name, "nosniff")]
    if v and v.strip().lower() == "nosniff":
        return chk("xcto", name, "PASS", 10, 10, v)
    if v:
        return chk("xcto", name, "WARN", 0, 10, v, "should be exactly 'nosniff'", fix)
    return chk("xcto", name, "FAIL", 0, 10, None, "missing", fix)


REFERRER_POINTS = {"no-referrer": 10, "same-origin": 10, "strict-origin": 10,
                   "strict-origin-when-cross-origin": 10, "origin": 7, "origin-when-cross-origin": 7,
                   "no-referrer-when-downgrade": 6, "same-origin-by-default": 6, "unsafe-url": 0}


def check_referrer(h):
    name, v = "Referrer-Policy", hget(h, "referrer-policy")
    fix = [("set", name, REC[name])]
    if not v:
        return chk("referrer", name, "WARN", 5, 10, None, "missing: relies on the browser default", fix)
    tokens = [t.strip().lower() for t in v.split(",")]
    known = [t for t in tokens if t in REFERRER_POINTS]
    if not known:
        return chk("referrer", name, "WARN", 0, 10, v, "unrecognised value", fix)
    pts = REFERRER_POINTS[known[-1]]
    if known[-1] == "unsafe-url":
        return chk("referrer", name, "FAIL", 0, 10, v, "leaks the full URL to every site", fix)
    return chk("referrer", name, "PASS" if pts == 10 else "WARN", pts, 10, v,
               "" if pts == 10 else "a stricter policy is recommended", fix if pts < 10 else None)


def check_permissions(h):
    name, v = "Permissions-Policy", hget(h, "permissions-policy")
    if v:
        return chk("permissions", name, "PASS", 5, 5, v)
    fix = [("set", name, REC[name])]
    if hget(h, "feature-policy"):
        return chk("permissions", name, "WARN", 2, 5, hget(h, "feature-policy"), "old Feature-Policy name only", fix)
    return chk("permissions", name, "WARN", 0, 5, None, "missing: browser features are not restricted", fix)


def check_coop(h):
    name, v = "Cross-Origin-Opener-Policy", hget(h, "cross-origin-opener-policy")
    fix = [("set", name, REC[name])]
    if v and v.lower() == "same-origin":
        return chk("coop", name, "PASS", 4, 4, v)
    if v and v.lower() == "same-origin-allow-popups":
        return chk("coop", name, "PASS", 3, 4, v)
    if v:
        return chk("coop", name, "WARN", 0, 4, v, "unsafe-none gives no isolation", fix)
    return chk("coop", name, "WARN", 0, 4, None, "missing", fix)


def check_corp(h):
    name, v = "Cross-Origin-Resource-Policy", hget(h, "cross-origin-resource-policy")
    fix = [("set", name, REC[name])]
    if v and v.lower() in ("same-origin", "same-site"):
        return chk("corp", name, "PASS", 4, 4, v)
    if v:
        return chk("corp", name, "WARN", 2, 4, v, "any site may embed your resources", fix)
    return chk("corp", name, "WARN", 0, 4, None, "missing", fix)


def check_coep(h):
    name, v = "Cross-Origin-Embedder-Policy", hget(h, "cross-origin-embedder-policy")
    return chk("coep", name, "INFO", 0, 0, v, "" if v else "not set (optional: only for cross-origin isolation)")


def check_xss(h):
    v = hget(h, "x-xss-protection")
    if v is None:
        return None
    if v.strip() == "0":
        return chk("xss", "X-XSS-Protection", "INFO", 0, 0, v, "disabled, as recommended")
    return chk("xss", "X-XSS-Protection", "INFO", 0, 0, v, "legacy header: set 0 and rely on a CSP")


def check_leaks(h):
    found, pts = [], 5
    server = hget(h, "server")
    fix = []
    if server and re.search(r"\d", server):
        pts -= 2
        found.append(f"Server: {server}")
        fix.append(("remove", "Server"))
    for hdr, cost in (("x-powered-by", 2), ("x-aspnet-version", 1), ("x-aspnetmvc-version", 1), ("x-generator", 1)):
        if hdr in h:
            pts -= cost
            shown = "-".join("X" if part == "x" else part.capitalize() for part in hdr.split("-"))
            found.append(f"{shown}: {hget(h, hdr)}")
            fix.append(("remove", shown))
    if not found:
        return chk("leaks", "Version disclosure", "PASS", 5, 5, server, "no software versions exposed")
    return chk("leaks", "Version disclosure", "WARN", max(pts, 0), 5, None, "reveals " + "; ".join(found), fix)


def check_cookies(h, https):
    cookies = h.get("set-cookie")
    if not cookies:
        return None
    total = ok = 0
    problems = []
    for raw in cookies:
        name = raw.split("=", 1)[0].strip() or "?"
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        flags = {"HttpOnly": "httponly" in attrs, "SameSite": any(a.startswith("samesite=") for a in attrs)}
        if https:
            flags["Secure"] = "secure" in attrs
        missing = [k for k, v in flags.items() if not v]
        total += len(flags)
        ok += sum(flags.values())
        if "samesite=none" in attrs and "secure" not in attrs:
            missing.append("Secure (required with SameSite=None)")
            ok = max(ok - 1, 0)
        if missing:
            problems.append(f"{name}: missing {', '.join(missing)}")
    pts = round(10 * ok / total) if total else 10
    status = "PASS" if not problems else "WARN" if pts >= 5 else "FAIL"
    note = "; ".join(problems[:4]) + (" ..." if len(problems) > 4 else "")
    return chk("cookies", f"Set-Cookie ({len(cookies)})", status, pts, 10, None,
               note or "every cookie has Secure, HttpOnly and SameSite")


def check_https_redirect(start_url, chain, error=None):
    if error:
        return chk("https", "HTTP to HTTPS redirect", "INFO", 0, 0, None, f"plain HTTP not reachable ({error})")
    final = chain[-1]["url"] if chain else start_url
    if urllib.parse.urlsplit(final).scheme != "https":
        return chk("https", "HTTP to HTTPS redirect", "FAIL", 0, 5, None, "plain HTTP is not redirected to HTTPS")
    if chain and chain[0]["status"] in (301, 308):
        return chk("https", "HTTP to HTTPS redirect", "PASS", 5, 5, str(chain[0]["status"]), "permanent redirect")
    return chk("https", "HTTP to HTTPS redirect", "WARN", 3, 5, str(chain[0]["status"]) if chain else None,
               "temporary redirect: use 301 or 308")


def check_cors(h, origin=EVIL_ORIGIN):
    acao = hget(h, "access-control-allow-origin")
    creds = (hget(h, "access-control-allow-credentials") or "").strip().lower() == "true"
    name = "CORS (foreign Origin)"
    if not acao:
        return chk("cors", name, "PASS", 5, 5, None, "foreign origins get no CORS access")
    if acao == origin:
        if creds:
            return chk("cors", name, "FAIL", 0, 5, acao, "reflects any Origin and allows credentials")
        return chk("cors", name, "WARN", 2, 5, acao, "reflects any Origin")
    if acao == "null":
        return chk("cors", name, "FAIL", 0, 5, acao, "trusts the null origin")
    if acao == "*":
        if creds:
            return chk("cors", name, "FAIL", 0, 5, acao, "wildcard with credentials")
        return chk("cors", name, "WARN", 3, 5, acao, "open to every site (fine for public APIs only)")
    return chk("cors", name, "PASS", 5, 5, acao, "restricted to a specific origin")


def compute(checks):
    scored = [c for c in checks if c["max"] > 0]
    total = sum(c["max"] for c in scored)
    score = round(100 * sum(c["earned"] for c in scored) / total) if total else 0
    grade = "A+" if score >= 97 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 \
        else "D" if score >= 50 else "F"
    if grade == "A+" and any(c["status"] in ("WARN", "FAIL") for c in checks):
        grade = "A"
    return score, grade


def analyze(pairs, final_url, chain=None, start_url=None, cors_pairs=None, http_probe=None):
    h = hmap(pairs)
    https = urllib.parse.urlsplit(final_url).scheme == "https"
    checks = [check_hsts(h, https), check_csp(h), check_frame(h), check_xcto(h), check_referrer(h),
              check_permissions(h), check_coop(h), check_corp(h), check_coep(h), check_xss(h),
              check_leaks(h), check_cookies(h, https)]
    if start_url and urllib.parse.urlsplit(start_url).scheme == "http":
        checks.append(check_https_redirect(start_url, chain or []))
    if http_probe is not None:
        checks.append(check_https_redirect(http_probe["url"], http_probe["chain"], http_probe["error"]))
    if cors_pairs is not None:
        checks.append(check_cors(hmap(cors_pairs)))
    checks = [c for c in checks if c]
    score, grade = compute(checks)
    return {"checks": checks, "score": score, "grade": grade}


# ----------------------------------------------------- fix snippets ----

def collect_fixes(checks):
    sets, removes = [], []
    for c in checks:
        if c["status"] in ("PASS", "INFO"):
            continue
        for kind, name, *val in c["fix"]:
            item = (name, val[0]) if kind == "set" else name
            target = sets if kind == "set" else removes
            if item not in target:
                target.append(item)
    return sets, removes


def snippets(checks, fmt):
    sets, removes = collect_fixes(checks)
    if not sets and not removes:
        return "# Nothing to fix: no missing or weak headers were found."
    lines = []
    if fmt == "nginx":
        lines += [f'add_header {n} "{v}" always;' for n, v in sets]
        for n in removes:
            lines.append("server_tokens off;" if n.lower() == "server"
                         else f"proxy_hide_header {n};   # or fastcgi_hide_header for PHP-FPM")
    elif fmt == "apache":
        lines += [f'Header always set {n} "{v}"' for n, v in sets]
        for n in removes:
            lines += ["ServerTokens Prod", "ServerSignature Off"] if n.lower() == "server" \
                else [f"Header always unset {n}"]
    elif fmt == "caddy":
        lines.append("header {")
        lines += [f'    {n} "{v}"' for n, v in sets]
        lines += [f"    -{n}" for n in removes]
        lines.append("}")
    else:  # express
        lines.append("app.use((req, res, next) => {")
        lines += [f'  res.setHeader("{n}", "{v}");' for n, v in sets]
        for n in removes:
            lines.append('  res.removeHeader("%s");' % n)
        lines += ["  next();", "});"]
    return "\n".join(lines)


# ------------------------------------------------------------ baseline ----

def snapshot(r):
    h = hmap(r["headers"])
    return {"grade": r["grade"], "score": r["score"], "saved": dt.datetime.now(dt.timezone.utc).isoformat(),
            "headers": {k: hget(h, k) for k in TRACKED if hget(h, k)}}


def compare_baseline(old, r):
    """Human-readable differences; the first element is flagged as a regression."""
    notes, regression = [], False
    if GRADES.index(r["grade"]) < GRADES.index(old["grade"]):
        notes.append(f"grade dropped {old['grade']} -> {r['grade']}")
        regression = True
    elif r["grade"] != old["grade"]:
        notes.append(f"grade improved {old['grade']} -> {r['grade']}")
    new = snapshot(r)["headers"]
    for k in sorted(old["headers"]):
        if k not in new:
            notes.append(f"removed: {k}")
            regression = True
        elif new[k] != old["headers"][k]:
            notes.append(f"changed: {k}")
    for k in sorted(set(new) - set(old["headers"])):
        notes.append(f"added: {k}")
    return notes, regression


def save_baseline(path, results):
    p = Path(path)
    data = json.loads(p.read_text()) if p.exists() else {}
    saved = 0
    for r in results:
        if r["grade"] != "-":
            data[r["url"]] = snapshot(r)
            saved += 1
    p.write_text(json.dumps(data, indent=2))
    return saved


def apply_baseline(results, path):
    data = json.loads(Path(path).read_text())
    for r in results:
        old = data.get(r["url"])
        if r["grade"] == "-":
            continue
        if old is None:
            r["notes"].append("not in baseline")
            continue
        notes, regression = compare_baseline(old, r)
        r["notes"] += notes or ["same as baseline"]
        r["regression"] = regression
    return results


# ------------------------------------------------------------- running ----

def new_result(raw, url):
    return {"input": raw, "url": url or raw, "final_url": None, "status": None, "error": None, "chain": [],
            "headers": [], "checks": [], "score": None, "grade": "-", "notes": [], "regression": False}


def scan_one(item, args):
    raw, url = item
    res = new_result(raw, url)
    if url is None:
        res["error"] = "invalid URL"
        return res
    extra = args.extra_headers
    kw = dict(timeout=args.timeout, verify=not args.insecure, max_redirects=args.max_redirects,
              user_agent=args.user_agent)
    got = fetch(url, follow=not args.no_follow, extra_headers=extra, **kw)
    res.update(final_url=got["final_url"], status=got["status"], chain=got["chain"],
               headers=got["headers"], error=got["error"])
    if got["error"]:
        return res
    cors_pairs = http_probe = None
    if args.cors:
        probe = fetch(got["final_url"], follow=False, extra_headers={**extra, "Origin": EVIL_ORIGIN}, **kw)
        cors_pairs = None if probe["error"] else probe["headers"]
    parts = urllib.parse.urlsplit(url)
    if args.check_http and parts.scheme == "https":
        http_probe = fetch(f"http://{parts.hostname}/", follow=True, extra_headers=extra, **kw)
    res.update(analyze(got["headers"], got["final_url"], got["chain"], url, cors_pairs, http_probe))
    return res


def run_parallel(items, args, quiet):
    workers = max(1, min(8, len(items)))
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=err_console,
                  transient=True, disable=quiet or len(items) < 2) as progress:
        progress.add_task(f"scanning {len(items)} sites", total=None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(lambda it: scan_one(it, args), items))


def sort_results(results):
    results.sort(key=lambda r: (-1 if r["grade"] == "-" else r["score"]))
    return results


# -------------------------------------------------------------- output ----

def issue_counts(r):
    fails = sum(c["status"] == "FAIL" for c in r["checks"])
    warns = sum(c["status"] == "WARN" for c in r["checks"])
    return fails, warns


def render_summary(results):
    table = Table(title="ChronoHeaders", header_style="bold cyan")
    table.add_column("Site", overflow="fold")
    table.add_column("Grade")
    table.add_column("Score", justify="right")
    table.add_column("Issues")
    for r in results:
        if r["error"]:
            table.add_row(escape(r["url"]), "[bold red]ERROR[/]\n[dim]" + escape(r["error"]) + "[/]", "-", "-")
            continue
        fails, warns = issue_counts(r)
        cell = f"[bold {GRADE_COLOR[r['grade']]}]{r['grade']}[/]"
        if r["notes"]:
            style = "red" if r["regression"] else "dim"
            cell += f"\n[{style}]{escape('; '.join(r['notes']))}[/]"
        table.add_row(escape(r["url"]), cell, str(r["score"]), f"{fails} fail, {warns} warn")
    console.print(table)


def print_report(title, sections):
    table = Table(title=escape(title), header_style="bold cyan", show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value", overflow="fold")
    for name, rows in sections:
        if not rows:
            continue
        table.add_section()
        table.add_row(f"[bold cyan]{name}[/]", "")
        for k, v, *style in rows:
            v = escape(str(v))
            table.add_row(escape(str(k)), f"[{style[0]}]{v}[/]" if style and style[0] else v)
    console.print(table)


def cut(text, n=70):
    text = text.replace("\n", " ")
    return text if len(text) <= n else text[:n - 3] + "..."


def check_row(c):
    detail = c["note"] or (cut(c["value"]) if c["value"] else "")
    if c["status"] == "PASS" and c["value"] and c["note"]:
        detail = f"{cut(c['value'], 40)} ({c['note']})"
    elif c["status"] == "PASS" and c["value"]:
        detail = cut(c["value"])
    pts = f" [{c['earned']}/{c['max']}]" if c["max"] else ""
    return (c["name"], f"{c['status']}{pts}  {detail}".strip(), STATUS_COLOR[c["status"]])


def render_report(r):
    if r["error"]:
        print_report(r["url"], [("SUMMARY", [("Status", "ERROR", "bold red"), ("Error", r["error"], "red")])])
        return
    summary = [("Grade", r["grade"], "bold " + GRADE_COLOR[r["grade"]]), ("Score", f"{r['score']}/100"),
               ("HTTP status", r["status"])]
    if r["final_url"] != r["url"]:
        summary.append(("Final URL", r["final_url"]))
    redirects = [(f"{i}.", f"{hop['status']}  {hop['url']}") for i, hop in enumerate(r["chain"], 1)] \
        if len(r["chain"]) > 1 else []
    notes = [("note", n, "red" if r["regression"] else "dim") for n in r["notes"]]
    print_report(r["url"], [("SUMMARY", summary), ("CHECKS", [check_row(c) for c in r["checks"]]),
                            ("REDIRECTS", redirects), ("BASELINE", notes)])


def to_json(r):
    out = {"url": r["url"], "final_url": r["final_url"], "http_status": r["status"], "grade": r["grade"],
           "score": r["score"], "error": r["error"], "redirects": r["chain"], "notes": r["notes"],
           "regression": r["regression"],
           "checks": [{"id": c["id"], "name": c["name"], "status": c["status"], "points": c["earned"],
                       "max": c["max"], "value": c["value"], "note": c["note"]} for c in r["checks"]]}
    return out


def below(grade, minimum):
    return minimum is not None and (grade == "-" or GRADES.index(grade) < GRADES.index(minimum))


# ------------------------------------------------------------ commands ----

def parse_extra_headers(values):
    out = {}
    for v in values or []:
        name, sep, value = v.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"bad header {v!r} (use 'Name: value')")
        out[name.strip()] = value.strip()
    return out


def cmd_scan(args):
    try:
        args.extra_headers = parse_extra_headers(args.header)
    except ValueError as exc:
        err_console.print(f"[red]{escape(str(exc))}[/]")
        return 2
    items = load_urls(args.urls, args.file)
    if not items:
        err_console.print("[red]Give at least one URL, or -f FILE.[/]")
        return 2
    results = run_parallel(items, args, args.json)
    if args.baseline:
        try:
            apply_baseline(results, args.baseline)
        except (OSError, ValueError, KeyError) as exc:
            err_console.print(f"[red]Cannot use baseline:[/] {escape(str(exc))}")
            return 2
    sort_results(results)
    if args.save_baseline:
        n = save_baseline(args.save_baseline, results)
        err_console.print(f"[green]Baseline saved:[/] {n} site(s) -> {escape(args.save_baseline)}")
    if args.json:
        print(json.dumps([to_json(r) for r in results], indent=2))
    else:
        if len(results) > 1:
            render_summary(results)
        if len(results) == 1 or args.details:
            for r in results:
                render_report(r)
    bad = any(r["error"] or r["regression"] or below(r["grade"], args.min_grade) for r in results)
    return 1 if bad else 0


def cmd_raw(args):
    try:
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(errors="replace")
    except OSError as exc:
        err_console.print(f"[red]Cannot read file:[/] {escape(str(exc))}")
        return 2
    pairs, status = parse_raw(text)
    if not pairs:
        err_console.print("[red]No headers found. Paste the output of `curl -sI URL`.[/]")
        return 2
    url = ("http" if args.http else "https") + "://" + "raw-input.invalid/"
    res = new_result(args.file, url)
    res.update(final_url=url, status=status, headers=pairs, **analyze(pairs, url))
    if args.json:
        print(json.dumps(to_json(res), indent=2))
    else:
        render_report(res)
    return 1 if below(res["grade"], args.min_grade) else 0


def cmd_fix(args):
    args.extra_headers, args.header = {}, []
    args.no_follow, args.max_redirects, args.user_agent = False, 5, UA
    args.cors = args.check_http = False
    try:
        url = normalize_url(args.url)
    except ValueError as exc:
        err_console.print(f"[red]{escape(str(exc))}[/]")
        return 2
    res = scan_one((args.url, url), args)
    if res["error"]:
        err_console.print(f"[red]Could not scan:[/] {escape(res['error'])}")
        return 1
    err_console.print(f"[bold]{escape(res['url'])}[/]  grade [bold {GRADE_COLOR[res['grade']]}]{res['grade']}[/]"
                      f"  ({res['score']}/100). Config for [bold]{args.fmt}[/]:")
    print(snippets(res["checks"], args.fmt))
    err_console.print("[dim]Test in a staging copy first. Roll out CSP with Report-Only before enforcing.[/]")
    return 0


# ----------------------------------------------------------------- CLI ----

def build_parser():
    parser = argparse.ArgumentParser(
        prog="chronoheaders",
        description="ChronoHeaders - grade HTTP security headers. Part of the CHRONO SUITE.",
        epilog=f"Dev: {DEV}  |  {DISCLAIMER}")
    parser.add_argument("-V", "--version", action="version", version=f"ChronoHeaders {VERSION} (Dev: {DEV})")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{scan,raw,fix}")

    def net(p):
        p.add_argument("-t", "--timeout", type=float, default=10.0, help="timeout in seconds (default 10)")
        p.add_argument("-k", "--insecure", action="store_true", help="don't verify the TLS certificate")

    p = sub.add_parser("scan", help="fetch and grade one or many sites (default command)")
    p.add_argument("urls", nargs="*", help="URL or host (https:// is assumed)")
    p.add_argument("-f", "--file", metavar="FILE", help="file with one URL per line (# for comments)")
    net(p)
    p.add_argument("--no-follow", action="store_true", help="don't follow redirects")
    p.add_argument("--max-redirects", type=int, default=5, help="redirect limit (default 5)")
    p.add_argument("-H", "--header", action="append", metavar="'Name: value'", help="extra request header (repeatable)")
    p.add_argument("--user-agent", default=UA, help="User-Agent to send")
    p.add_argument("--cors", action="store_true", help="also test CORS with a foreign Origin")
    p.add_argument("--check-http", action="store_true", help="also check that http:// redirects to HTTPS")
    p.add_argument("-d", "--details", action="store_true", help="full report for every site")
    p.add_argument("--min-grade", choices=GRADES, help="exit 1 if any site grades below this")
    p.add_argument("--baseline", metavar="FILE", help="compare with a saved baseline (regressions exit 1)")
    p.add_argument("--save-baseline", metavar="FILE", help="save grades and headers (after comparing)")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("raw", help="grade headers pasted from `curl -I` or DevTools")
    p.add_argument("file", help="file with the headers, or - for stdin")
    p.add_argument("--http", action="store_true", help="the page was served over HTTP, not HTTPS")
    p.add_argument("--min-grade", choices=GRADES, help="exit 1 if the grade is below this")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.set_defaults(func=cmd_raw)

    p = sub.add_parser("fix", help="print config snippets that fix the missing or weak headers")
    p.add_argument("url")
    p.add_argument("--for", dest="fmt", choices=FORMATS, default="nginx", help="server format (default nginx)")
    net(p)
    p.set_defaults(func=cmd_fix)
    return parser


def main():
    parser = build_parser()
    argv = sys.argv[1:]
    if not argv:
        show_banner()
        parser.print_help()
        sys.exit(0)
    if argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help", "-V", "--version"):
        argv.insert(0, "scan")  # `chronoheaders example.com` still works
    args = parser.parse_args(argv)
    try:
        sys.exit(args.func(args))
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/]")
        sys.exit(130)
    except OSError as exc:
        err_console.print(f"[red]Error:[/] {escape(str(exc))}")
        sys.exit(2)


if __name__ == "__main__":
    main()
