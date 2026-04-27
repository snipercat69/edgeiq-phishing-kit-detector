#!/usr/bin/env python3
"""
EdgeIQ Labs — Phishing Kit Detector
Phishing artifact detection, brand impersonation analysis,
JavaScript analysis, infrastructure fingerprinting.
"""

import argparse
import json
import os
import re
import socket
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple

# ─────────────────────────────────────────────
# ANSI helpers
# ─────────────────────────────────────────────
_GRN = '\033[92m'; _YLW = '\033[93m'; _RED = '\033[91m'; _CYA = '\033[96m'
_BLD = '\033[1m'; _RST = '\033[0m'; _MAG = '\033[35m'

def ok(t):    return f"{_GRN}{t}{_RST}"
def warn(t):  return f"{_YLW}{t}{_RST}"
def fail(t):  return f"{_RED}{t}{_RST}"
def info(t):  return f"{_CYA}{t}{_RST}"
def bold(t):  return f"{_BLD}{t}{_RST}"

# ─────────────────────────────────────────────
# Licensing
# ─────────────────────────────────────────────
LICENSE_FILE = Path.home() / ".edgeiq" / "license.key"

def is_pro():
    if LICENSE_FILE.exists():
        key = LICENSE_FILE.read().strip()
        if key in ("bundle", "pro"):
            return True
    email = os.environ.get("EDGEIQ_EMAIL", "").strip().lower()
    if email in ("gpalmieri21@gmail.com",):
        return True
    return False

# ─────────────────────────────────────────────
# Brand signatures (CSS refs, meta tags, keywords)
# ─────────────────────────────────────────────
BRAND_SIGNATURES = {
    "paypal": {
        "keywords": ["paypal", "pay pal", "paypal.com", "paypalusercontent"],
        "domains": ["paypal.com", "paypalobjects.com"],
        "css": ["paypal", "ppfonts", "spicepay"],
        "logos": ["paypal-logo", "paypal-mark", "paypal-icon"],
    },
    "amazon": {
        "keywords": ["amazon", "amazon.com", "amazonaws", "amazonservices"],
        "domains": ["amazon.com", "amazonaws.com", "amazonwebservices"],
        "css": ["amazon", "azfonts", "amazonui"],
        "logos": ["amazon-logo", "amazon-icon"],
    },
    "apple": {
        "keywords": ["apple", "apple.com", "icloud", "appleid"],
        "domains": ["apple.com", "icloud.com", "mzstatic.com"],
        "css": ["apple", "applelegacy", "apple-font"],
        "logos": ["apple-logo", "apple-icon", "apple-touch-icon"],
    },
    "google": {
        "keywords": ["google", "google.com", "googlesyndication", "googleapis"],
        "domains": ["google.com", "googleapis.com", "googleusercontent.com"],
        "css": ["google", "google-fonts", "material-icons"],
        "logos": ["google-logo", "google-icon"],
    },
    "microsoft": {
        "keywords": ["microsoft", "microsoftonline", "msft", "microsoftazure"],
        "domains": ["microsoft.com", "microsoftonline.com", "azure.com"],
        "css": ["microsoft", "msfonts", "microsoft-ui"],
        "logos": ["microsoft-logo", "ms-icon"],
    },
    "facebook": {
        "keywords": ["facebook", "fb.com", "facebookinc", "facebookbusiness"],
        "domains": ["facebook.com", "fbcdn.net", "facebookinc.com"],
        "css": ["facebook", "fbfonts", "facebook-ui"],
        "logos": ["facebook-logo", "fb-icon", "fb-logo"],
    },
    "instagram": {
        "keywords": ["instagram", "instagr.am", "igimg", "instagramstatic"],
        "domains": ["instagram.com", "igimg.com", "instagramstatic.com"],
        "css": ["instagram", "igfonts"],
        "logos": ["instagram-logo", "ig-icon"],
    },
    "netflix": {
        "keywords": ["netflix", "netflix.com", "nflxext", "nflximg"],
        "domains": ["netflix.com", "nflxvideo.net", "nflximg.com"],
        "css": ["netflix", "nffonts"],
        "logos": ["netflix-logo", "nflx-icon"],
    },
    "linkedin": {
        "keywords": ["linkedin", "linkedin.com", "licdn", "linkedininc"],
        "domains": ["linkedin.com", "licdn.com", "linkedininc.com"],
        "css": ["linkedin", "lifonts"],
        "logos": ["linkedin-logo", "li-icon"],
    },
    "chase": {
        "keywords": ["chase", "chase.com", "chasebank", "jpmorganchase"],
        "domains": ["chase.com", "chaseonline.com"],
        "css": ["chase", "chase-bank"],
        "logos": ["chase-logo", "chase-icon"],
    },
    "bank of america": {
        "keywords": ["bank of america", "bofa", "bankofamerica", "bofa.com"],
        "domains": ["bankofamerica.com", "bofa.com"],
        "css": ["bofa", "bac-fonts"],
        "logos": ["bofa-logo"],
    },
}

# Suspicious TLDs common in phishing
PHISHING_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".link", ".loan", ".online", ".site", ".website", ".space", ".pw")

# Phishing URL path patterns
PHISHING_PATHS = [
    "login", "account", "verify", "secure", "update", "confirm", "signin",
    "authenticate", "validate", "banking", "payment", "password", "reset",
    "recovery", "support", "alert", "notification", "limited", "unusual",
    "suspended", "reauthorize", "re-authenticate",
]

# Free hosting providers
FREE_HOSTING = [
    "000webhost", "altervista", "byethost", "free.fr", "freenom",
    "github.io", "herokuapp", "infinityfree", "netlify", "render.com",
    "surge.sh", "vercel.app", "w3spaces", "web.app", "firebaseapp",
    "000webhost.com", "github.com", "gitlab.io", "bitbucket.org",
    "angelfire", "tripod", "webs", "jimdo", "weebly", "wix",
]

# Credential harvest endpoints (common patterns)
HARVEST_PATTERNS = [
    r"/collect", r"/submit", r"/capture", r"/harvest", r"/steal",
    r"/log", r"/record", r"/save", r"/store", r"/crecord",
    r"/auth/submit", r"/api/auth", r"/api/login", r"/api/collect",
    r"/formHandler", r"/form_proc", r"/formmail", r"/cgi-bin",
    r"/login/process", r"/verify.php", r"/check.php", r"/auth.php",
]

# ─────────────────────────────────────────────
# URL fetching
# ─────────────────────────────────────────────
def fetch_url(url: str, timeout: int = 15) -> Tuple[Optional[str], Optional[str]]:
    """Fetch URL content and return (html, error)."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) EdgeIQ-Phishing-Detector/1.0"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "text/plain" not in content_type:
                return None, "Not HTML content"
            html = resp.read().decode("utf-8", errors="ignore")
            return html[:200000], None  # Truncate large responses
    except Exception as e:
        return None, str(e)

# ─────────────────────────────────────────────
# HTML parsing
# ─────────────────────────────────────────────
def extract_html_features(html: str, url: str) -> Dict:
    """Extract phishing-relevant features from HTML."""
    features = {
        "forms": [],
        "form_actions": [],
        "inputs": [],
        "hidden_fields": [],
        "autocomplete_fields": [],
        "external_resources": [],
        "brand_refs": {},
        "suspicious_js": [],
        "redirects": [],
        "iframes": [],
        "meta_tags": {},
        "title": "",
        "text_content": "",
    }

    # Extract title
    title_match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    if title_match:
        features["title"] = title_match.group(1).strip()

    # Extract forms
    form_pattern = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        inputs = re.findall(r"<input[^>]+>", form_html, re.IGNORECASE)
        features["forms"].append({
            "action": action_match.group(1) if action_match else "",
            "inputs": inputs,
        })
        if action_match:
            features["form_actions"].append(action_match.group(1))

    # Extract inputs (all forms)
    input_pattern = re.compile(r"<input[^>]+>", re.IGNORECASE)
    for inp in input_pattern.finditer(html):
        inp_str = inp.group(0)
        features["inputs"].append(inp_str)
        if "type=" in inp_str:
            t = re.search(r'type=["\']([^"\']+)["\']', inp_str, re.IGNORECASE)
            if t and t.group(1).lower() in ("password", "hidden"):
                features["hidden_fields"].append(inp_str)
        if "autocomplete=" in inp_str and "on" in inp_str.lower():
            features["autocomplete_fields"].append(inp_str)

    # External resources
    css_pattern = re.compile(r'href=["\']([^"\']+\.css[^"\']*)["\']', re.IGNORECASE)
    js_pattern = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
    img_pattern = re.compile(r'src=["\']([^"\']+\.(jpg|png|gif|svg|ico)[^"\']*)["\']', re.IGNORECASE)
    link_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

    features["external_resources"] = {
        "css": css_pattern.findall(html),
        "js": js_pattern.findall(html),
        "images": img_pattern.findall(html),
    }

    # Meta tags
    meta_pattern = re.compile(r"<meta[^>]+>", re.IGNORECASE)
    for m in meta_pattern.finditer(html):
        name_match = re.search(r'name=["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
        prop_match = re.search(r'property=["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
        content_match = re.search(r'content=["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
        if name_match and content_match:
            features["meta_tags"][name_match.group(1).lower()] = content_match.group(1)
        elif prop_match and content_match:
            features["meta_tags"][prop_match.group(1).lower()] = content_match.group(1)

    # Ifames
    iframe_pattern = re.compile(r"<iframe[^>]+>", re.IGNORECASE)
    for fr in iframe_pattern.finditer(html):
        features["iframes"].append(fr.group(0))

    # Extract text content
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)
    features["text_content"] = text[:5000].lower()

    return features

# ─────────────────────────────────────────────
# Brand impersonation detection
# ─────────────────────────────────────────────
def detect_brand_impersonation(html: str, url: str, brands: List[str] = None) -> List[Dict]:
    """Detect brand impersonation from HTML content."""
    detected = []
    html_lower = html.lower()

    brands_to_check = list(BRAND_SIGNATURES.keys()) if not brands else brands
    url_lower = url.lower()

    for brand in brands_to_check:
        if brand not in BRAND_SIGNATURES:
            continue

        sig = BRAND_SIGNATURES[brand]
        score = 0
        matched = []

        # Check keywords
        for kw in sig["keywords"]:
            if kw in html_lower or kw in url_lower:
                score += 3
                matched.append(f"keyword: {kw}")

        # Check domain references (external resources from brand domain)
        for domain in sig["domains"]:
            if domain in html_lower:
                score += 4
                matched.append(f"external: {domain}")

        # Check CSS filenames
        for css in sig["css"]:
            if css in html_lower:
                score += 2
                matched.append(f"css: {css}")

        # Check meta tags (OG tags for brand)
        og_title = sig["meta_tag"] if "meta_tag" in sig else f"{brand} official"
        if any(sig["keywords"][0] in html_lower for sig in [sig]):
            score += 1

        if score >= 4:
            detected.append({
                "brand": brand,
                "confidence": min(score * 12, 99),
                "matched": matched[:8],
                "score": score,
            })

    # Sort by confidence
    detected.sort(key=lambda x: x["confidence"], reverse=True)
    return detected

# ─────────────────────────────────────────────
# Phishing artifact scoring
# ─────────────────────────────────────────────
def score_phishing_artifacts(features: Dict, html: str, url: str) -> Dict:
    """Score the page on phishing indicators."""
    score = 0
    indicators = []

    # Form action pointing to different domain (credential capture)
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc

    for action in features.get("form_actions", []):
        if action and not action.startswith("/") and not action.startswith("#"):
            action_parsed = urllib.parse.urlparse(action)
            if action_parsed.netloc and action_parsed.netloc != domain:
                score += 30
                indicators.append(f"Form action → external domain: {action_parsed.netloc}")
                # Check if it's a harvest endpoint
                for pat in HARVEST_PATTERNS:
                    if re.search(pat, action, re.IGNORECASE):
                        score += 15
                        indicators.append(f"Harvest endpoint detected: {action}")

    # Hidden password fields
    for inp in features.get("hidden_fields", []):
        if "password" in inp.lower():
            score += 15
            indicators.append("Hidden password field — likely credential capture")

    # Autocomplete on sensitive fields
    score += len(features.get("autocomplete_fields", [])) * 3
    if features.get("autocomplete_fields"):
        indicators.append(f"Autocomplete enabled on {len(features['autocomplete_fields'])} sensitive fields")

    # Multiple forms (login + payment + PIN)
    form_count = len(features.get("forms", []))
    if form_count >= 3:
        score += 15
        indicators.append(f"Multiple forms ({form_count}) — login + payment pattern")
    elif form_count >= 2:
        score += 8
        indicators.append(f"Multiple forms ({form_count})")

    # Suspicious number of external resources from different domains
    all_ext = []
    for category in features.get("external_resources", {}).values():
        all_ext.extend(category)
    unique_ext_domains = set()
    for res in all_ext:
        try:
            parsed = urllib.parse.urlparse(res)
            if parsed.netloc:
                unique_ext_domains.add(parsed.netloc)
        except:
            pass
    if len(unique_ext_domains) > 5:
        score += 12
        indicators.append(f"Heavy external resource loading ({len(unique_ext_domains)} domains)")
    if len(all_ext) > 20:
        score += 8
        indicators.append(f"Large number of external resources ({len(all_ext)})")

    # Check for suspicious JS (credential harvest patterns)
    js_content = " ".join(features.get("external_resources", {}).get("js", []))
    susp_js = [
        ("keylog", "Keylogger detection"),
        ("onkeypress", "Keyboard capture"),
        ("onkeydown", "Keyboard capture"),
        ("credential", "Credential harvesting variable"),
        ("password", "Password variable"),
        ("localstorage", "localStorage data exfiltration"),
        ("sessionstorage", "sessionStorage exfiltration"),
        ("eval(atob", "Obfuscated code (base64 eval)"),
        ("String.fromCharCode", "Obfuscated string construction"),
        ("crypto", "Cryptomining or crypto-related"),
        ("etherscan", "Cryptowallet drain pattern"),
    ]
    for pattern, desc in susp_js:
        if pattern in js_content.lower():
            score += 12
            indicators.append(f"JS: {desc}")

    # Check text content for phishing keywords
    text = features.get("text_content", "")
    phishing_text = [
        "verify your account", "update your information", "confirm your identity",
        "account suspended", "unusual activity", "click here immediately",
        "failure to verify", "limited time offer", "URGENT",
        "your account has been locked", "security alert",
    ]
    for phrase in phishing_text:
        if phrase in text:
            score += 10
            indicators.append(f"Phishing text phrase: '{phrase}'")

    # Suspicious title
    title = features.get("title", "").lower()
    for phrase in phishing_text:
        if phrase in title:
            score += 8
            indicators.append(f"Phishing title: '{features['title']}'")

    # Iframe usage (often used in phishing)
    if len(features.get("iframes", [])) > 0:
        score += 10
        indicators.append(f"iframe injection ({len(features['iframes'])} iframes)")

    # URL path analysis
    path = parsed_url.path.lower()
    for ph_path in PHISHING_PATHS:
        if f"/{ph_path}" in path:
            score += 5
            indicators.append(f"Phishing path pattern: {ph_path}")
            break

    # Domain age risk (suspicious TLD)
    tld = "." + domain.split(".")[-1] if domain else ""
    if tld.lower() in PHISHING_TLDS:
        score += 15
        indicators.append(f"Suspicious TLD: {tld} — common in phishing")

    # Free hosting detection
    for provider in FREE_HOSTING:
        if provider in domain.lower():
            score += 12
            indicators.append(f"Free hosting provider: {provider}")
            break

    return {
        "score": min(score, 100),
        "indicators": indicators[:20],
        "confidence": min(score, 99),
    }

# ─────────────────────────────────────────────
# Infrastructure analysis
# ─────────────────────────────────────────────
def analyze_infrastructure(url: str, html: str) -> Dict:
    """Analyze hosting infrastructure."""
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc

    result = {
        "domain": domain,
        "tld": None,
        "is_free_hosting": False,
        "is_suspicious_tld": False,
        "ip_resolved": None,
        "notes": [],
    }

    # TLD analysis
    parts = domain.split(".")
    if len(parts) >= 2:
        result["tld"] = "." + parts[-1]
        if result["tld"].lower() in PHISHING_TLDS:
            result["is_suspicious_tld"] = True
            result["notes"].append(f"Suspicious TLD: {result['tld']}")

    # Free hosting detection
    for provider in FREE_HOSTING:
        if provider in domain.lower():
            result["is_free_hosting"] = True
            result["notes"].append(f"Free hosting: {provider}")
            break

    # IP resolution
    try:
        ip = socket.gethostbyname(domain)
        result["ip_resolved"] = ip
        # Check for private/reserved
        ip_parts = [int(p) for p in ip.split('.')]
        if ip_parts[0] in (10, 127) or (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or (ip_parts[0] == 192 and ip_parts[1] == 168):
            result["notes"].append("Private IP resolved")
        else:
            result["notes"].append(f"IP: {ip}")
    except:
        result["notes"].append("Could not resolve IP")

    # URL shortener detection
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "j.mp"]
    for short in shorteners:
        if short in domain.lower():
            result["notes"].append(f"URL shortener: {short} — destination hidden")
            result["is_url_shortener"] = True

    return result

# ─────────────────────────────────────────────
# Main analyzer
# ─────────────────────────────────────────────
def analyze(url: Optional[str] = None, file_path: Optional[str] = None,
            brands: Optional[List[str]] = None, pro: bool = False,
            bundle: bool = False, output: Optional[str] = None) -> dict:
    print()
    print(f"{_CYA}{_BLD}╔{'═' * 54}╗{_RST}")
    print(f"{_CYA}{_BLD}║   Phishing Kit Detector — EdgeIQ Labs       ║{_RST}")
    print(f"{_CYA}{_BLD}╚{'═' * 54}╝{_RST}")
    print()

    tier = "BUNDLE" if bundle else ("PRO" if pro else "FREE")
    print(f"  {_MAG}▶{_RST} Tier: {tier}")

    html = None
    if file_path:
        if not os.path.exists(file_path):
            print(f"  {fail('✘')} File not found: {file_path}")
            return {}
        html = open(file_path).read()
        print(f"  {_MAG}▶{_RST} File: {bold(file_path)}")
    elif url:
        print(f"  {_MAG}▶{_RST} URL: {bold(url)}")
        print(f"  {info('⏳')} Fetching page...")
        html, err = fetch_url(url)
        if err:
            print(f"  {warn('⚠️ ')} Fetch error: {err}")
    else:
        print(f"  {fail('✘')} Provide --url or --file")
        return {}

    if not html or len(html) < 100:
        print(f"  {fail('✘')} No content to analyze")
        return {}

    print(f"  {_MAG}▶{_RST} Content: {len(html):,} bytes")
    print()
    print(f"  {info('⏳')} Extracting HTML features...")
    features = extract_html_features(html, url or "")
    print(f"  {info('⏳')} Scoring phishing artifacts...")
    artifacts = score_phishing_artifacts(features, html, url or "")
    print(f"  {info('⏳')} Detecting brand impersonation...")

    detected_brands = []
    if pro or bundle:
        detected_brands = detect_brand_impersonation(html, url or "", brands)
    elif brands:
        # Even on free, show top-level brand detection if specified
        detected_brands = detect_brand_impersonation(html, url or "", brands[:2])

    print(f"  {info('⏳')} Analyzing infrastructure...")
    infra = analyze_infrastructure(url or "", html)

    # Results
    results = {
        "url": url,
        "file": file_path,
        "artifacts": artifacts,
        "brands": detected_brands,
        "infrastructure": infra,
        "features": {
            "title": features.get("title", ""),
            "form_count": len(features.get("forms", [])),
            "form_actions": features.get("form_actions", []),
            "hidden_fields": len(features.get("hidden_fields", [])),
            "external_css": features["external_resources"].get("css", []),
            "external_js": features["external_resources"].get("js", []),
            "external_images": features["external_resources"].get("images", []),
            "iframes": len(features.get("iframes", [])),
        },
        "threat_level": "LOW",
    }

    # Print artifact analysis
    art_score = artifacts["score"]
    if art_score >= 50:
        thresh = fail("🔴 PHISHING KIT DETECTED")
    elif art_score >= 25:
        thresh = warn("🟡 SUSPICIOUS")
    else:
        thresh = ok("✔ Likely clean")

    print(f"  {thresh} ({artifacts['confidence']}% confidence)")
    print()
    if artifacts["indicators"]:
        print(f"  {bold('Phishing Indicators:')}")
        for ind in artifacts["indicators"][:15]:
            print(f"    ⚠️  {ind}")
        print()

    # Brand impersonation
    if detected_brands:
        for bd in detected_brands[:3]:
            conf = bd["confidence"]
            bc = fail if conf >= 70 else warn
            print(f"  {bc('🏷️ ')} Brand impersonation: {bold(bd['brand'].upper())} ({conf}% confidence)")
            for m in bd["matched"][:4]:
                print(f"    → {m}")
        print()

    # Infrastructure
    print(f"  {bold('Infrastructure:')}")
    print(f"    Domain: {infra['domain']}")
    if infra.get("tld"):
        print(f"    TLD: {infra['tld']}")
    for note in infra.get("notes", []):
        print(f"    • {note}")
    print()

    # Threat level
    if art_score >= 70 or (detected_brands and detected_brands[0]["confidence"] >= 80):
        threat = "CRITICAL"
    elif art_score >= 40:
        threat = "HIGH"
    elif art_score >= 20:
        threat = "MEDIUM"
    else:
        threat = "LOW"

    results["threat_level"] = threat

    print(f"  {'─' * 55}")
    print()
    tc = _RED if threat == "CRITICAL" else (_YLW if threat == "HIGH" else _GRN)
    print(f"=== Analysis Complete ===")
    print(f"  Threat Level: {tc}{bold(threat)}{_RST}")
    print(f"  Artifact Score: {art_score}/100 | Detected Brands: {len(detected_brands)}")

    if output:
        Path(output).write_text(json.dumps(results, indent=2))
        print(f"  {ok('✔')} JSON report saved: {output}")

    print()
    return results

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EdgeIQ Phishing Kit Detector")
    parser.add_argument("--url", help="Phishing URL to analyze")
    parser.add_argument("--file", help="Path to local HTML file")
    parser.add_argument("--brands", help="Comma-separated brand list (paypal,amazon,apple,google,microsoft,facebook,instagram,netflix,linkedin)")
    parser.add_argument("--pro", action="store_true", help="Enable Pro features")
    parser.add_argument("--bundle", action="store_true", help="Enable Bundle features")
    parser.add_argument("--output", help="Write JSON report to file")
    args = parser.parse_args()

    brands = [b.strip().lower() for b in args.brands.split(",")] if args.brands else None
    analyze(url=args.url, file_path=args.file, brands=brands,
            pro=args.pro, bundle=args.bundle, output=args.output)