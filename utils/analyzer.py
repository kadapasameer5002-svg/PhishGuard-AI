import re
from urllib.parse import urlparse
import socket

# Suspicious keywords commonly used in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "banking", 
    "wallet", "signin", "otp", "update"
]

# Risky Top-Level Domains (TLDs)
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".top", ".gq"
]

def validate_url(url: str) -> bool:
    """
    Validates if the URL has a correct structure and starts with http:// or https://
    """
    if not url:
        return False
    
    # Strip whitespace
    url = url.strip()
    
    # Check if starts with http:// or https://
    if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
        return False
        
    try:
        parsed = urlparse(url)
        # Must have at least scheme and network location (domain)
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # Simple domain name regex validation
        # Allows for IPs, localhosts, and standard domain names
        domain = parsed.hostname
        if not domain:
            return False
            
        return True
    except Exception:
        return False

def is_ip_address(hostname: str) -> bool:
    """
    Checks if the hostname is a valid IPv4 or IPv6 address.
    """
    if not hostname:
        return False
    
    # Check IPv4
    try:
        socket.inet_aton(hostname)
        return True
    except socket.error:
        pass
        
    # Check IPv6
    try:
        socket.inet_pton(socket.AF_INET6, hostname)
        return True
    except (socket.error, AttributeError):
        pass
        
    return False

def analyze_url(url: str) -> dict:
    """
    Performs static analysis on a URL to detect phishing indicators.
    Returns a dictionary of analysis results and detected issues.
    """
    url = url.strip()
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    analysis = {
        "https_check": {"result": "HTTPS Enabled", "risk_applied": False},
        "ip_check": {"result": "Clean (No IP in URL)", "risk_applied": False},
        "keyword_check": {"result": "No Suspicious Keywords", "detected": [], "risk_applied": False},
        "tld_check": {"result": "Safe TLD", "detected": "", "risk_applied": False},
        "length_check": {"result": "Normal Length", "length": len(url), "risk_applied": False},
        "special_char_check": {"result": "No Suspicious Characters", "details": [], "risk_applied": False}
    }
    
    detected_issues = []

    # 1. HTTPS Verification
    # Check if HTTPS is used
    if parsed.scheme.lower() == "https":
        analysis["https_check"] = {
            "result": "HTTPS Enabled",
            "risk_applied": False
        }
    else:
        analysis["https_check"] = {
            "result": "HTTPS Missing",
            "risk_applied": True
        }
        detected_issues.append("HTTPS Missing")

    # 2. IP Address Detection
    if is_ip_address(hostname):
        analysis["ip_check"] = {
            "result": "IP Address URL Detected",
            "risk_applied": True
        }
        detected_issues.append("IP Address URL Detected")
    else:
        analysis["ip_check"] = {
            "result": "Clean (Domain Name Used)",
            "risk_applied": False
        }

    # 3. Suspicious Keyword Detection
    # Check the entire URL for phishing terms (case insensitive)
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found_keywords:
        analysis["keyword_check"] = {
            "result": f"Suspicious Keywords Found: {', '.join(found_keywords)}",
            "detected": found_keywords,
            "risk_applied": True
        }
        for kw in found_keywords:
            detected_issues.append(f"Suspicious Keyword: {kw}")
    else:
        analysis["keyword_check"] = {
            "result": "No Suspicious Keywords",
            "detected": [],
            "risk_applied": False
        }

    # 4. Domain Extension (TLD) Analysis
    # Check if the hostname ends with one of the suspicious TLDs
    found_tld = None
    for tld in SUSPICIOUS_TLDS:
        if hostname.lower().endswith(tld):
            found_tld = tld
            break
            
    if found_tld:
        analysis["tld_check"] = {
            "result": f"Suspicious TLD Found: {found_tld}",
            "detected": found_tld,
            "risk_applied": True
        }
        detected_issues.append(f"Suspicious TLD: {found_tld}")
    else:
        analysis["tld_check"] = {
            "result": "Safe TLD",
            "detected": "",
            "risk_applied": False
        }

    # 5. URL Length Analysis
    if len(url) > 50:
        analysis["length_check"] = {
            "result": f"Long URL Detected ({len(url)} chars)",
            "length": len(url),
            "risk_applied": True
        }
        detected_issues.append("Long URL")
    else:
        analysis["length_check"] = {
            "result": "Normal Length",
            "length": len(url),
            "risk_applied": False
        }

    # 6. Special Character Analysis
    # Check for @, multiple dots, encoded characters (%), excessive hyphens (-)
    char_issues = []
    
    # @ character detection (used for obfuscating real domain in URL)
    if "@" in url:
        char_issues.append("@ character present (userinfo obfuscation)")
        
    # Multiple dots (usually > 3 in the whole URL, suggesting deep subdomains or phishing structure)
    if url.count(".") >= 4:  # e.g., 4 or more dots is highly suspicious
        char_issues.append("Excessive subdomains (multiple dots)")
        
    # Encoded characters detection (e.g. %2f, %20 to hide domain names)
    if "%" in url:
        char_issues.append("Encoded characters found in path/domain")
        
    # Excessive hyphens in domain/URL (often used to mimic brands, e.g., paytm-secure-login-update)
    if url.count("-") >= 3:
        char_issues.append("Excessive hyphens in URL")
        
    if char_issues:
        analysis["special_char_check"] = {
            "result": f"Suspicious Character(s) Found",
            "details": char_issues,
            "risk_applied": True
        }
        detected_issues.append("Suspicious Character Found")
    else:
        analysis["special_char_check"] = {
            "result": "No Suspicious Characters",
            "details": [],
            "risk_applied": False
        }

    return {
        "analysis": analysis,
        "detected_issues": detected_issues
    }
