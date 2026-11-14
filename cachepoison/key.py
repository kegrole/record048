"""Cache-key computation.

The cache key is a single string with four pipe-separated segments:

    host | normalized_path | normalized_query | key_header_names

* host             -- the request's Host header value (never the
                      absolute-form target host).
* normalized_path  -- output of normalize.normalize_path.
* normalized_query -- output of normalize.normalize_query.
* key_header_names -- names of the request headers declared to
                      participate in the key, lowercased, sorted
                      alphabetically, joined with commas.
"""

from .normalize import normalize_path, normalize_query

KEY_SEPARATOR = "|"


def compute_cache_key(host, path, query, key_headers):
    """Build the canonical cache-key string from already-normalized parts."""
    header_segment = ",".join(sorted(name.lower() for name in key_headers))
    return KEY_SEPARATOR.join([host or "", path or "/", query or "", header_segment])


def build_cache_key(host, raw_path, raw_query, key_headers,
                    query_mode="all", query_params=None):
    """Normalize path/query and compute the cache key for a request."""
    return compute_cache_key(
        host,
        normalize_path(raw_path),
        normalize_query(raw_query, mode=query_mode, params=query_params),
        key_headers,
    )


def raw_cache_key(host, raw_path, raw_query, key_headers):
    """Cache key as a non-normalizing CDN would compute it (raw path/query)."""
    return compute_cache_key(host, raw_path or "/", raw_query or "", key_headers)
