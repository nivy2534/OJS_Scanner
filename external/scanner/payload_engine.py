from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

def apply_payload_url(url, param, payload, mode="replace"):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if param not in query:
        return None

    original = query[param][0]

    if mode == "replace":
        query[param] = [payload]
    elif mode == "append":
        query[param] = [original + payload]
    elif mode == "prefix":
        query[param] = [payload + original]

    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def get_fuzz_params(params: dict, pattern: str = None):
    """Filter parameter mana yang difuzz, berdasarkan regex pattern."""
    if not pattern:
        return list(params.keys())
    return [p for p in params if re.search(pattern, p, re.IGNORECASE)]