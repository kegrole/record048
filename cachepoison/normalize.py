"""Path and query normalization for cache-key computation.

Normalization rules (all applied to the raw request path):

1. Percent-decode (so %2f becomes / before any structural handling).
2. Collapse duplicate slashes.
3. Resolve dot segments (. and ..) per RFC 3986 section 5.2.4.
4. Lowercase every segment (treats case differences as equivalent).
5. Drop the trailing slash (except for the root path /).

If the normalized path differs from the raw path, two requests that the
origin considers equivalent will produce different cache keys at a CDN
that does not normalize -- a cache-key split.
"""

from urllib.parse import parse_qsl, urlencode, unquote

QUERY_MODE_ALL = "all"
QUERY_MODE_IGNORE = "ignore"
QUERY_MODE_PARAMS = "params"

VALID_QUERY_MODES = (QUERY_MODE_ALL, QUERY_MODE_IGNORE, QUERY_MODE_PARAMS)


def normalize_path(path):
    """Return the canonical form of a URL path.

    Applies percent-decoding, duplicate-slash collapsing, dot-segment
    resolution, lowercasing, and trailing-slash removal.
    """
    if not path:
        return "/"
    decoded = unquote(path)
    segments = []
    for segment in decoded.split("/"):
        if segment in ("", "."):
            # Empty segments come from leading/duplicate/trailing slashes.
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment.lower())
    return "/" + "/".join(segments)


def path_split_risk(raw_path):
    """True when the raw path differs from its normalized form."""
    return normalize_path(raw_path) != raw_path


def normalize_query(query, mode=QUERY_MODE_ALL, params=None):
    """Return the canonical query-string component of a cache key.

    mode "all"    -> the raw query string participates verbatim.
    mode "ignore" -> the query string is excluded from the key ("").
    mode "params" -> only the listed parameter names participate,
                     sorted by name and re-encoded as k=v&k=v.
    """
    if mode == QUERY_MODE_IGNORE:
        return ""
    if mode == QUERY_MODE_ALL:
        return query or ""
    if mode == QUERY_MODE_PARAMS:
        wanted = {name.lower() for name in (params or [])}
        pairs = [
            (name, value)
            for name, value in parse_qsl(query or "", keep_blank_values=True)
            if name.lower() in wanted
        ]
        pairs.sort(key=lambda pair: (pair[0].lower(), pair[1]))
        return urlencode(pairs)
    raise ValueError("unknown query mode: %r" % (mode,))
