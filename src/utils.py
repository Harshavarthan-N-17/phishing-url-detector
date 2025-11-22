from urllib.parse import urlparse

def get_domain(url: str):
    try:
        return urlparse(url).netloc
    except Exception:
        return None
