# ml_features.py
import math
import re
from urllib.parse import urlparse
from collections import Counter

SUSPICIOUS_KEYWORDS = ["login","verify","secure","account","update","bank","signin","confirm","password","reset"]
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    probs = [v/len(s) for v in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url: str, page_analysis: dict=None) -> dict:
    u = url.strip()
    if not u.startswith(("http://","https://")):
        u = "http://" + u
    parsed = urlparse(u)
    domain = (parsed.netloc or "").lower().split(":")[0]
    path = parsed.path or ""
    scheme = parsed.scheme or ""

    feats = {}
    feats["url_length"] = len(u)
    feats["having_ip"] = 1 if IP_RE.match(domain) else 0
    feats["has_at"] = 1 if "@" in u else 0
    feats["num_hyphens"] = domain.count("-")
    feats["num_dots"] = domain.count(".")
    feats["num_subdomains"] = max(0, domain.count(".") - 1)
    feats["num_digits_in_domain"] = sum(c.isdigit() for c in domain)
    feats["has_https"] = 1 if scheme == "https" else 0
    feats["num_suspicious_keywords"] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in u.lower())
    feats["num_path_segments"] = len([p for p in path.split("/") if p])
    feats["domain_entropy"] = shannon_entropy(domain)

    # dynamic page features (if available)
    if page_analysis:
        feats["form_count"] = int(page_analysis.get("form_count", 0))
        feats["password_fields"] = int(page_analysis.get("password_fields", 0))
        feats["input_count"] = int(page_analysis.get("input_count", 0))
        feats["script_count"] = int(page_analysis.get("script_count", 0))
        feats["link_count"] = int(page_analysis.get("link_count", 0))
        feats["iframe_count"] = int(page_analysis.get("iframe_count", 0))
        final = page_analysis.get("final_url", "")
        feats["final_url_differs"] = 1 if final and (final.lower() != u.lower()) else 0
        # cross-domain form actions
        base_host = domain
        form_actions = page_analysis.get("form_actions", []) or []
        cross = 0
        for a in form_actions:
            if a and a.startswith("http"):
                try:
                    #from urllib.parse import urlparse
                    ah = urlparse(a).netloc.split(":")[0].lower()
                    if ah and ah != base_host:
                        cross += 1
                except:
                    pass
        feats["cross_domain_form_actions"] = cross
    else:
        feats["form_count"] = 0
        feats["password_fields"] = 0
        feats["input_count"] = 0
        feats["script_count"] = 0
        feats["link_count"] = 0
        feats["iframe_count"] = 0
        feats["final_url_differs"] = 0
        feats["cross_domain_form_actions"] = 0

    return feats
