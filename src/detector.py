"""import re
import difflib
from urllib.parse import urlparse

# ---------------------------
# Load blacklist file
# ---------------------------
def load_blacklist():
    try:
        with open("src/blacklist.txt", "r") as file:
            return [line.strip().lower() for line in file.readlines()]
    except FileNotFoundError:
        return []

blacklist = load_blacklist()


# ---------------------------
# Phishing detection function
# ---------------------------
def check_url_safety(url):
    reasons = []
    score = 0

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full_url = url.lower()

    # 1️⃣ Check if domain in blacklist
    if domain in blacklist:
        reasons.append("Domain found in blacklist database.")
        score += 3

    # 2️⃣ URL contains '@' → redirects to another site (common phishing trick)
    if "@" in full_url:
        reasons.append("Contains '@' symbol — may redirect to a different site.")
        score += 3

    # 3️⃣ URL contains multiple dots, commas, or unusual separators
    if ".." in domain or "," in domain or ",," in domain:
        reasons.append("Contains multiple dots or commas (obfuscation attempt).")
        score += 2

    # 4️⃣ Too many subdomains (e.g., login.paypal.security.verify.example.com)
    if domain.count('.') > 3:
        reasons.append("Too many subdomains (may try to mimic trusted sites).")
        score += 2

    # 5️⃣ Suspicious or encoded characters (%20, !, $, etc.)
    if re.search(r"[%@!$^*()_=+{}|\\<>]", full_url):
        reasons.append("Contains unusual or encoded characters (possible phishing).")
        score += 2

    # 6️⃣ Suspicious keywords commonly found in phishing URLs
    keywords = [
        "login", "verify", "update", "bank", "secure", "confirm", "free", "gift",
        "win", "password", "signin", "account", "support", "unlock", "urgent",
        "alert", "limited", "claim", "reset", "safe", "bonus", "offer"
    ]
    if any(k in full_url for k in keywords):
        reasons.append("Contains phishing-related keywords.")
        score += 2

    # 7️⃣ URL shorteners (hide real domain)
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co", "is.gd", "shorturl"]
    if any(s in domain for s in shorteners):
        reasons.append("Uses URL shortener (possible concealment).")
        score += 2

    # 8️⃣ HTTP instead of HTTPS (unsafe protocol)
    if parsed.scheme != "https":
        reasons.append("Does not use HTTPS protocol.")
        score += 1

    # 9️⃣ Domain look-alike check using similarity ratio
    trusted_domains = [
        "google.com", "chatgpt.com", "openai.com", "paypal.com",
        "facebook.com", "amazon.com", "skcet.ac.in"
    ]
    for trusted in trusted_domains:
        similarity = difflib.SequenceMatcher(None, domain, trusted).ratio()
        if similarity > 0.8 and domain != trusted:
            reasons.append(f"Domain is visually similar to '{trusted}' (possible impersonation).")
            score += 3

    # 🔟 Too many numbers in domain (auto-generated)
    if sum(c.isdigit() for c in domain) > 5:
        reasons.append("Contains too many numbers (auto-generated domain).")
        score += 2

    # 11️⃣ Unusually long URL
    if len(url) > 100:
        reasons.append("URL is unusually long (possible redirection).")
        score += 1

    # 12️⃣ Suspicious or uncommon top-level domains (TLD)
    if not re.search(r"\.(com|org|net|edu|gov|in|co|io|ai|info|biz|me|dev|tech|ac|uk)$", domain):
        reasons.append("Uses uncommon or suspicious top-level domain.")
        score += 1

    # ✅ Final Decision based on score
    if score >= 4:
        return False, reasons if reasons else ["Suspicious behavior detected."]
    else:
        return True, ["URL appears legitimate."] """




# src/detector.py
import re
import difflib
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from pathlib import Path
from typing import Tuple, List, Dict, Any

# ---------------------------
# Load blacklist file
# ---------------------------
def load_blacklist():
    try:
        base = Path(__file__).resolve().parent
        with open(base / "blacklist.txt", "r") as file:
            return [line.strip().lower() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        return []

blacklist = load_blacklist()

# ---------------------------
# Phishing detection function (existing rule-based)
# ---------------------------
def check_url_safety(url):
    """
    Existing rule-based checker (kept as you provided).
    Returns (is_safe: bool, reasons: list[str], score:int)
    """
    reasons = []
    score = 0

    parsed = urlparse(url)
    domain = (parsed.netloc or "").lower()
    full_url = (url or "").lower()

    # 1️⃣ Check if domain in blacklist
    if domain in blacklist:
        reasons.append("Domain found in blacklist database.")
        score += 3

    # 2️⃣ URL contains '@' → redirects to another site (common phishing trick)
    if "@" in full_url:
        reasons.append("Contains '@' symbol — may redirect to a different site.")
        score += 3

    # 3️⃣ URL contains multiple dots, commas, or unusual separators
    if ".." in domain or "," in domain or ",," in domain:
        reasons.append("Contains multiple dots or commas (obfuscation attempt).")
        score += 2

    # 4️⃣ Too many subdomains (e.g., login.paypal.security.verify.example.com)
    if domain.count('.') > 3:
        reasons.append("Too many subdomains (may try to mimic trusted sites).")
        score += 2

    # 5️⃣ Suspicious or encoded characters (%20, !, $, etc.)
    if re.search(r"[%@!$^*()_=+{}|\\<>]", full_url):
        reasons.append("Contains unusual or encoded characters (possible phishing).")
        score += 2

    # 6️⃣ Suspicious keywords commonly found in phishing URLs
    keywords = [
        "login", "verify", "update", "bank", "secure", "confirm", "free", "gift",
        "win", "password", "signin", "account", "support", "unlock", "urgent",
        "alert", "limited", "claim", "reset", "safe", "bonus", "offer" ,
    ]
    if any(k in full_url for k in keywords):
        reasons.append("Contains phishing-related keywords.")
        score += 2

    # 7️⃣ URL shorteners (hide real domain)
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co", "is.gd", "shorturl"]
    if any(s in domain for s in shorteners):
        reasons.append("Uses URL shortener (possible concealment).")
        score += 2

    # 8️⃣ HTTP instead of HTTPS (unsafe protocol)
    if parsed.scheme != "https":
        reasons.append("Does not use HTTPS protocol.")
        score += 2

    # 9️⃣ Domain look-alike check using similarity ratio
    trusted_domains = [
        "google.com", "chatgpt.com", "openai.com", "paypal.com",
        "facebook.com", "amazon.com", "skcet.ac.in"
    ]
    for trusted in trusted_domains:
        similarity = difflib.SequenceMatcher(None, domain, trusted).ratio()
        if similarity > 0.8 and domain != trusted:
            reasons.append(f"Domain is visually similar to '{trusted}' (possible impersonation).")
            score += 3

    # 🔟 Too many numbers in domain (auto-generated)
    if sum(c.isdigit() for c in domain) > 5:
        reasons.append("Contains too many numbers (auto-generated domain).")
        score += 2

    # 11️⃣ Unusually long URL
    if len(url) > 100:
        reasons.append("URL is unusually long (possible redirection).")
        score += 1

    # 12️⃣ Suspicious or uncommon top-level domains (TLD)
    if not re.search(r"\.(com|org|net|edu|gov|in|co|io|ai|info|biz|me|dev|tech|ac|uk)$", domain):
        reasons.append("Uses uncommon or suspicious top-level domain.")
        score += 1

    is_safe = (score < 4)
    if is_safe:
        return True, ["URL appears legitimate."], score
    else:
        return False, reasons if reasons else ["Suspicious behavior detected."], score

# ---------------------------
# Page scraping to extract dynamic page features
# ---------------------------
def scrape_page_for_analysis(url: str, timeout: int = 8) -> Dict[str, Any]:
    """
    Fetch page (single request) and compute simple counts:
    - form_count, password_fields, input_count, script_count, link_count, iframe_count
    - collects form 'action' attributes
    - final_url after redirects
    Returns a dict compatible with your ml_features.page_analysis expectations.
    """
    out = {
        "form_count": 0,
        "password_fields": 0,
        "input_count": 0,
        "script_count": 0,
        "link_count": 0,
        "iframe_count": 0,
        "final_url": "",
        "form_actions": []
    }
    try:
        headers = {"User-Agent": "Mozilla/5.0 (SecurityResearch/1.0)"}
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        html = resp.text or ""
        out["final_url"] = resp.url or ""
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        out["form_count"] = len(forms)
        inputs = soup.find_all("input")
        out["input_count"] = len(inputs)
        out["password_fields"] = sum(1 for i in inputs if (i.get("type") or "").lower() == "password")
        out["script_count"] = len(soup.find_all("script"))
        out["link_count"] = len(soup.find_all("a"))
        out["iframe_count"] = len(soup.find_all("iframe"))
        actions = []
        for f in forms:
            a = f.get("action") or ""
            if a:
                # convert relative actions to absolute using base url
                try:
                    actions.append(urljoin(resp.url, a))
                except:
                    actions.append(a)
        out["form_actions"] = actions
    except Exception as e:
        # treat as no dynamic data but capture exception message if needed
        out["error"] = str(e)
    return out

# ---------------------------
# ML integration (uses your ml_predict module)
# ---------------------------
try:
    from ml_predict import predict_url as ml_predict_url
except Exception as e:
    # lazy warning if import fails; keep functionality for pure rule-based usage
    ml_predict_url = None

# ---------------------------
# High-level analyze function (ML-first, fallback to rules)
# ---------------------------
def analyze_url(url: str, ml_high_threshold: float = 0.8, ml_low_threshold: float = 0.4) -> Dict[str, Any]:
    """
    High-level orchestrator:
    1. Scrape page for dynamic features (safely)
    2. Run ML prediction first (if ML available)
    3. If ML confident (>= high threshold) -> immediate verdict
    4. If ML uncertain -> run rule-based check and combine signals
    Returns a dict with:
      - input_url, ml_result, rule_result, combined_verdict, reasons, combined_score
    """
    result = {
        "input_url": url,
        "ml": None,
        "rule": None,
        "final_verdict": None,
        "final_score": None,
        "reasons": []
    }

    # 1) gather page analysis (best-effort)
    page_analysis = scrape_page_for_analysis(url)

    # 2) ML prediction (if module available)
    if ml_predict_url:
        try:
            ml_out = ml_predict_url(url, page_analysis=page_analysis)
            # ml_out expected: {'probability': float, 'prediction': int, 'raw_features': {...}}
            result["ml"] = ml_out
            prob = float(ml_out.get("probability") or 0.0)
            # If ML is very confident -> use it
            if prob >= ml_high_threshold:
                result["final_verdict"] = "phishing (ml_high_confidence)"
                result["final_score"] = prob * 100.0
                result["reasons"].append(f"ML model probability {prob:.3f} >= {ml_high_threshold}")
                return result
            # If ML predicts safe with high confidence (prob very low)
            if prob <= (1 - ml_high_threshold):
                result["final_verdict"] = "safe (ml_high_confidence)"
                result["final_score"] = prob * 100.0
                result["reasons"].append(f"ML model low probability {prob:.3f} <= {1-ml_high_threshold}")
                return result
            # Otherwise ML uncertain => fallthrough to rule based
        except Exception as e:
            # If ML fails, note it and continue with rule-based only
            result["ml_error"] = str(e)

    # 3) Rule-based checks
    try:
        is_safe, reasons_list, rule_score = check_url_safety(url)
        result["rule"] = {"is_safe": is_safe, "reasons": reasons_list, "score": rule_score}
    except Exception as e:
        result["rule_error"] = str(e)
        is_safe = True
        reasons_list = ["Rule-based check failed"]

    # 4) Combine signals: simple heuristic combine
        # 4) Combine signals: simple heuristic combine
    combined_score = rule_score
    ml_prob = 0.0
    if result.get("ml") and result["ml"].get("probability") is not None:
        ml_prob = float(result["ml"]["probability"])
        # convert ml_prob (0..1) to 0..10 score contribution (tunable)
        combined_score += ml_prob * 10.0

    result["final_score"] = combined_score

    # 🧠 Tuned decision thresholds
    if combined_score >= 8:
        result["final_verdict"] = "likely_phishing"
    elif combined_score >= 5:
        result["final_verdict"] = "suspicious"
    else:
        result["final_verdict"] = "safe"

    # Stitch reasons: ML reasons + rule reasons
    if result.get("ml"):
        result["reasons"].append(f"ML probability: {ml_prob:.3f}")
    if reasons_list:
        result["reasons"].extend(reasons_list)

    return result


