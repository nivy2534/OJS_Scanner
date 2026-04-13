from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def apply_payload(url, param, payload, mode="replace"):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if param not in query:
        return None

    original = query[param][0]

    if mode == "replace":
        query[param] = payload
    elif mode == "append":
        query[param] = original + payload
    elif mode == "prefix":
        query[param] = payload + original

    new_query = urlencode(query, doseq=True)

    return urlunparse(parsed._replace(query=new_query))