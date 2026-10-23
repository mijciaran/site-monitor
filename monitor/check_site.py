#!/usr/bin/env python3
"""
Site integrity monitor for myirishjeweler.com.

Runs from GitHub Actions (outside the web server) and checks that:
  1. Every known JavaScript file still has its known-good SHA-256 hash.
  2. The monitored pages load no script from an unexpected domain or an unknown local path.
  3. No page contains the known skimmer indicators.
  4. The webshell paths still return 404.
  5. (Optional) The Content-Security-Policy header is present.

Writes any problems to problems.txt and exits 0. The workflow decides how to alert.
Uses only the Python standard library.
"""
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())
BASE = CONFIG["base_url"].rstrip("/")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

problems = []
notes = []


def fetch(path, attempts=3):
    """Return (status, headers, body bytes). Retries network errors and 429/5xx."""
    url = urljoin(BASE + "/", path.lstrip("/"))
    sep = "&" if "?" in url else "?"
    url = f"{url}{sep}monitor={int(time.time())}"  # bypass caches
    last = None
    for i in range(attempts):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Cache-Control": "no-cache"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and i < attempts - 1:
                time.sleep(10 * (i + 1))
                continue
            return e.code, e.headers, e.read()
        except Exception as e:  # network error, timeout
            last = e
            time.sleep(10 * (i + 1))
    raise RuntimeError(f"could not fetch {path}: {last}")


class ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs, self.inline, self._in_inline = [], [], False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            a = dict(attrs)
            if a.get("src"):
                self.srcs.append(a["src"])
            else:
                self._in_inline = True
                self.inline.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_inline = False

    def handle_data(self, data):
        if self._in_inline:
            self.inline[-1] += data


def host_allowed(host):
    for pattern in CONFIG["allowed_script_hosts"]:
        if pattern.startswith("*."):
            if host == pattern[2:] or host.endswith(pattern[1:]):
                return True
        elif host == pattern:
            return True
    return False


def check_js_files():
    for path, expected in CONFIG["js_files"].items():
        try:
            status, _, body = fetch(path)
        except RuntimeError as e:
            problems.append(f"JS file {path}: {e}")
            continue
        if status != 200:
            problems.append(f"JS file {path}: HTTP {status}")
            continue
        digest = hashlib.sha256(body).hexdigest()
        if digest != expected:
            hits = [s for s in CONFIG["forbidden_strings"] if s.encode() in body]
            problems.append(
                f"JS file {path} CHANGED: size {len(body)} bytes, sha256 {digest}"
                + (f" - contains {hits}" if hits else "")
            )


def check_pages(known_local):
    require_csp = CONFIG.get("require_csp", False)
    for path in CONFIG["pages"]:
        try:
            status, headers, body = fetch(path)
        except RuntimeError as e:
            problems.append(f"Page {path}: {e}")
            continue
        if status != 200:
            problems.append(f"Page {path}: HTTP {status}")
            continue
        html = body.decode("utf-8", "replace")
        for s in CONFIG["forbidden_strings"]:
            if s in html:
                problems.append(f"Page {path} contains forbidden string '{s}'")
        p = ScriptParser()
        p.feed(html)
        for src in p.srcs:
            u = urlparse(urljoin(BASE + "/", src))
            if u.hostname and u.hostname.lower() not in (urlparse(BASE).hostname,):
                if not host_allowed(u.hostname.lower()):
                    problems.append(f"Page {path} loads script from UNEXPECTED host: {u.geturl()}")
            else:
                if u.path not in known_local and not any(u.path.startswith(x) for x in CONFIG["allowed_local_prefixes"]):
                    problems.append(f"Page {path} loads UNKNOWN local script: {u.path}")
        for i, code in enumerate(p.inline):
            for s in CONFIG["forbidden_inline"]:
                if s in code:
                    problems.append(f"Page {path} inline script #{i} contains '{s}'")
        if require_csp:
            csp = headers.get("Content-Security-Policy", "")
            if "connect-src" not in csp:
                problems.append(f"Page {path}: Content-Security-Policy header missing or has no connect-src")


def check_must_404():
    for path in CONFIG["must_be_404"]:
        try:
            status, _, _ = fetch(path)
        except RuntimeError as e:
            problems.append(f"{path}: {e}")
            continue
        if status != 404:
            problems.append(f"{path} returned HTTP {status} (expected 404) - backdoor may be back")


def main():
    check_js_files()
    check_pages(set(CONFIG["js_files"].keys()))
    check_must_404()
    out = HERE.parent / "problems.txt"
    if problems:
        out.write_text("\n".join(problems) + "\n")
        print("PROBLEMS FOUND:")
        print("\n".join(problems))
    else:
        if out.exists():
            out.unlink()
        print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
