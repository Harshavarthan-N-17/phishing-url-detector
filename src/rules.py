import os
import re

# Path to blacklist file (kept in same folder as rules.py)
BLACKLIST_FILE = os.path.join(os.path.dirname(__file__), "blacklist.txt")

# Load domains from blacklist.txt (each line = 1 domain)
if os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE, "r") as f:
        BLACKLISTED_DOMAINS = [line.strip().lower() for line in f if line.strip()]
else:
    # fallback in case blacklist.txt is missing
    BLACKLISTED_DOMAINS = [
        "phishy.com",
        "malicious.net",
        "badwebsite.org"
    ]

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "bank",
    "account",
    "update",
    "secure"
]

def check_url_rules(url: str) -> bool:
    """
    Returns True if suspicious, False if safe
    """

    # Rule 1: If URL contains '@' symbol → often used in phishing
    if "@" in url:
        return True

    # Rule 2: If URL is very long → suspicious
    if len(url) > 75:
        return True

    # Rule 3: If URL does not use HTTPS
    if not url.startswith("https://"):
        return True

    # Rule 4: If contains suspicious keywords
    if any(word in url.lower() for word in SUSPICIOUS_KEYWORDS):
        return True

    # Rule 5: If it has lots of numbers in domain
    domain = url.split("/")[2] if "//" in url else url
    if sum(c.isdigit() for c in domain) > 5:
        return True

    # Rule 6: If domain is blacklisted
    if any(blacklisted in domain for blacklisted in BLACKLISTED_DOMAINS):
        return True

    return False
