# cachepoison

Web cache poisoning / cache-key confusion detector. Pure Python standard
library — no third-party dependencies.

A CDN that normalizes URLs differently from the origin (or that keys its
cache on attacker-controlled input) can be tricked into storing a private
or forged response under one key and serving it to everyone. This tool
replays request/response cases against a cache configuration and reports
exactly where the key can be split or poisoned.

## Usage

    python -m cachepoison.cli --cases demo/cases.json --out out/report.json

Prints a one-line summary to stdout (case count, risk count, risk-type
distribution) and writes the full JSON report to --out.

Run the tests:

    cd tests && python -m unittest test_cachepoison -v
    # or from the repo root:
    python -m unittest tests.test_cachepoison -v

## Cache-key format

Every case produces one canonical cache-key string with four
pipe-separated segments:

    host|normalized_path|normalized_query|key_header_names

- **host** — the request's Host header value. When the request target is
  in absolute-form (http://host/path) and disagrees with the Host header,
  the key still uses the Host header, and the mismatch is reported.
- **normalized_path** — see normalization rules below.
- **normalized_query** — depends on the configured query mode.
- **key_header_names** — the request headers declared to participate in
  the key (config key_headers), lowercased, sorted alphabetically, joined
  with commas.

## Path normalization rules

normalize.normalize_path applies, in order:

1. Percent-decoding (%2f becomes a real slash before structural handling).
2. Duplicate-slash collapsing (//a///b -> /a/b).
3. Dot-segment resolution per RFC 3986 5.2.4 (/a/b/../c -> /a/c).
4. Lowercasing of every segment (/API/V1 -> /api/v1).
5. Trailing-slash removal, except for the root / (/items/ -> /items).

If the raw path differs from its normalized form, the case is flagged as
path_normalization_split: two URLs the origin treats as equivalent map to
different cache keys at any CDN that does not normalize identically, so an
attacker can choose which variant gets cached. The evidence reports both
the raw key and the normalized key.

## Query-string participation

Config query_mode controls how the query string enters the key:

- all — the whole query string participates verbatim.
- ignore — the query string is excluded (key segment is empty). Safe when
  explicitly configured, e.g. for static assets with tracking parameters.
- params — only the parameter names listed in query_params participate,
  sorted by name and re-encoded as k=v&k=v.

## Risk rules

- **host_mismatch** — the request target is absolute-form and its host
  differs from the Host header. Evidence reports both values.
- **path_normalization_split** — raw path differs from its normalized
  form (dot segments, %2f, duplicate slashes, case, trailing slash).
- **trusted_proxy_header_in_key** — a client-controllable proxy header
  (X-Forwarded-Host, X-Forwarded-Server, X-Host, Forwarded, ...) is
  declared as part of the cache key. Anyone can mint arbitrary keys.
- **missing_vary** — the response content actually depends on a request
  header (declared via the case's response varies_on list) that the Vary
  response header does not cover. Evidence names the offending header.
  Vary: * covers everything.
- **public_with_set_cookie** — Cache-Control: public authorizes shared
  caching while Set-Cookie marks the response user-specific; the conflict
  is reported with both sources named.

## Report format

Each entry in the report's results list contains:

- case_id — the case identifier from the input.
- verdict — "risk" or "safe".
- risk_types — sorted list of triggered risk-rule identifiers.
- evidence — list of human-readable strings backing the verdict.
- cache_key — the normalized cache-key string.

The summary block aggregates case count, risk count, and the risk-type
distribution.

## Case file format

    {
      "config": {"query_mode": "all", "query_params": [], "key_headers": []},
      "cases": [
        {
          "case_id": "example",
          "request":  {"method": "GET", "target": "/path?q=1",
                       "headers": {"Host": "example.com"}},
          "response": {"status": 200, "headers": {"Vary": "Origin"},
                       "varies_on": ["Origin"]},
          "config":   {"query_mode": "ignore"}
        }
      ]
    }

target may be origin-form (/path?q=1) or absolute-form
(http://host/path?q=1). Per-case config overrides the top-level config.
varies_on declares which request headers the origin's response content
actually depends on (ground truth used for the Vary check).

## Layout

- cachepoison/normalize.py — path and query normalization
- cachepoison/key.py — cache-key computation
- cachepoison/vary.py — Vary header analysis
- cachepoison/policy.py — trusted proxy headers, Cache-Control conflicts
- cachepoison/detector.py — per-case risk evaluation
- cachepoison/report.py — report assembly and summary
- cachepoison/cli.py, cachepoison/__main__.py — command-line entry points
- demo/cases.json — eight demo cases (six risks, two safe)
- tests/test_cachepoison.py — unittest suite covering every rule
