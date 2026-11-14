"""Cache-policy checks: trusted proxy headers and Cache-Control conflicts."""

TRUSTED_PROXY_HEADERS = frozenset({
    "x-forwarded-host",
    "x-forwarded-server",
    "x-forwarded",
    "x-host",
    "x-original-host",
    "x-original-url",
    "x-rewrite-url",
    "forwarded",
})


def proxy_headers_in_key(key_headers, trusted=None):
    """Return key-participating headers that are client-controlled proxy headers.

    If a CDN is configured to trust headers such as X-Forwarded-Host and
    those headers feed the cache key, any client can mint arbitrary keys.
    """
    trusted = (TRUSTED_PROXY_HEADERS if trusted is None
               else {name.lower() for name in trusted})
    return sorted(
        {name for name in key_headers if name.lower() in trusted},
        key=str.lower,
    )


def parse_cache_control(value):
    """Parse a Cache-Control header into a set of lowercase directives."""
    if not value:
        return set()
    return {
        token.strip().split("=", 1)[0].lower()
        for token in value.split(",")
        if token.strip()
    }


def public_with_set_cookie(response_headers):
    """True when Cache-Control: public coexists with a Set-Cookie header.

    "public" authorizes shared caches to store the response while
    Set-Cookie marks it as user-specific -- a direct conflict that can
    leak one user's personalized response to everyone.
    """
    lowered = {name.lower(): value for name, value in response_headers.items()}
    directives = parse_cache_control(lowered.get("cache-control", ""))
    return "public" in directives and "set-cookie" in lowered
