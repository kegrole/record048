"""Vary-header analysis.

A response whose content depends on a request header must list that
header in its Vary response header; otherwise a shared cache may serve
a response personalized for one request to every other request.
"""


def parse_vary(vary_value):
    """Parse a Vary header value into a set of lowercase field names."""
    if not vary_value:
        return set()
    return {token.strip().lower() for token in vary_value.split(",") if token.strip()}


def missing_vary_entries(vary_value, varies_on):
    """Return the sorted list of headers in varies_on that Vary fails to cover.

    "Vary: *" covers every header (and disables shared caching entirely).
    """
    vary_names = parse_vary(vary_value)
    if "*" in vary_names:
        return []
    missing = {name.lower(): name for name in (varies_on or [])}
    uncovered = [original for lowered, original in missing.items()
                 if lowered not in vary_names]
    return sorted(uncovered, key=str.lower)
