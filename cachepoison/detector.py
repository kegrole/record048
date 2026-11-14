"""Per-case cache-poisoning detection.

Each case describes one request/response exchange plus the cache
configuration it is evaluated under:

    {
      "case_id": "...",
      "request":  {"method": "GET", "target": "/path?q=1",
                   "headers": {"Host": "example.com", ...}},
      "response": {"status": 200, "headers": {...},
                   "varies_on": ["Origin"]},
      "config":   {"query_mode": "all|ignore|params",
                   "query_params": [...],
                   "key_headers": [...],
                   "trusted_proxy_headers": [...]}
    }

"target" may be origin-form (/path?q=1) or absolute-form
(http://host/path?q=1).  "varies_on" declares which request headers the
response content actually depends on (ground truth from the origin).
"""

from urllib.parse import urlsplit

from .key import build_cache_key, raw_cache_key
from .normalize import normalize_path, normalize_query
from .policy import proxy_headers_in_key, public_with_set_cookie
from .vary import missing_vary_entries

VERDICT_RISK = "risk"
VERDICT_SAFE = "safe"

RISK_HOST_MISMATCH = "host_mismatch"
RISK_PATH_SPLIT = "path_normalization_split"
RISK_PROXY_HEADER_IN_KEY = "trusted_proxy_header_in_key"
RISK_MISSING_VARY = "missing_vary"
RISK_PUBLIC_SET_COOKIE = "public_with_set_cookie"

DEFAULT_CONFIG = {
    "query_mode": "all",
    "query_params": [],
    "key_headers": [],
    "trusted_proxy_headers": None,
}


def _merge_config(defaults, override):
    config = dict(DEFAULT_CONFIG)
    config.update(defaults or {})
    config.update(override or {})
    return config


def _header_lookup(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _split_target(target):
    """Return (target_host, path, query) for origin- or absolute-form targets."""
    parts = urlsplit(target)
    host = parts.netloc or None
    path = parts.path or "/"
    return host, path, parts.query


def analyze_case(case, default_config=None):
    """Analyze one case and return a report entry dict."""
    config = _merge_config(default_config, case.get("config"))
    request = case.get("request", {})
    response = case.get("response", {})
    req_headers = request.get("headers", {})
    resp_headers = response.get("headers", {})

    target = request.get("target", "/")
    target_host, raw_path, raw_query = _split_target(target)
    host_header = _header_lookup(req_headers, "Host")
    key_host = host_header if host_header is not None else (target_host or "")

    key_headers = list(config.get("key_headers") or [])
    query_mode = config.get("query_mode", "all")
    query_params = config.get("query_params") or []

    norm_path = normalize_path(raw_path)
    cache_key = build_cache_key(key_host, raw_path, raw_query, key_headers,
                                query_mode=query_mode, query_params=query_params)

    risks = []
    evidence = []

    # 1. Host header disagrees with an absolute-form request target.
    if target_host and host_header and target_host.lower() != host_header.lower():
        risks.append(RISK_HOST_MISMATCH)
        evidence.append(
            "Host header %r disagrees with absolute-form request target "
            "host %r (target %r); cache key uses the Host header value"
            % (host_header, target_host, target)
        )

    # 2. Path changes under normalization -> equivalent URLs, different keys.
    if norm_path != raw_path:
        risks.append(RISK_PATH_SPLIT)
        raw_key = raw_cache_key(key_host, raw_path, raw_query, key_headers)
        evidence.append(
            "path %r normalizes to %r; equivalent URLs produce different "
            "cache keys: raw key %r vs normalized key %r"
            % (raw_path, norm_path, raw_key, cache_key)
        )

    # 3. Client-controlled proxy headers adopted into the cache key.
    trusted = config.get("trusted_proxy_headers")
    adopted = proxy_headers_in_key(key_headers, trusted)
    if adopted:
        risks.append(RISK_PROXY_HEADER_IN_KEY)
        evidence.append(
            "cache key adopts trusted proxy header(s) %s; clients can "
            "mint arbitrary cache keys" % ", ".join(repr(h) for h in adopted)
        )

    # 4. Response content varies on a request header missing from Vary.
    varies_on = response.get("varies_on") or []
    missing = missing_vary_entries(_header_lookup(resp_headers, "Vary"), varies_on)
    for header_name in missing:
        risks.append(RISK_MISSING_VARY)
        evidence.append(
            "response content varies with request header %r but the Vary "
            "response header does not cover it" % header_name
        )

    # 5. Cache-Control: public together with Set-Cookie.
    if public_with_set_cookie(resp_headers):
        risks.append(RISK_PUBLIC_SET_COOKIE)
        evidence.append(
            "conflicting response directives: 'Cache-Control: public' "
            "authorizes shared caching while 'Set-Cookie' marks the "
            "response user-specific"
        )

    verdict = VERDICT_RISK if risks else VERDICT_SAFE
    return {
        "case_id": case.get("case_id", ""),
        "verdict": verdict,
        "risk_types": sorted(set(risks)),
        "evidence": evidence,
        "cache_key": cache_key,
    }


def analyze_cases(cases, default_config=None):
    """Analyze a list of cases and return report entries in order."""
    return [analyze_case(case, default_config) for case in cases]
