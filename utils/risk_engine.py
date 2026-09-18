def calculate_risk(analysis_results: dict) -> tuple:
    """
    Calculates the phishing risk score based on static analysis checks.
    Caps the final score at 100.
    Returns:
        (risk_score: int, risk_level: str)
    """
    score = 0
    analysis = analysis_results.get("analysis", {})
    
    # 1. HTTPS Check (Risk: +20)
    if analysis.get("https_check", {}).get("risk_applied", False):
        score += 20
        
    # 2. IP Address Check (Risk: +25)
    if analysis.get("ip_check", {}).get("risk_applied", False):
        score += 25
        
    # 3. Suspicious Keyword Check (Risk: +15)
    if analysis.get("keyword_check", {}).get("risk_applied", False):
        score += 15
        
    # 4. Domain TLD Check (Risk: +20)
    if analysis.get("tld_check", {}).get("risk_applied", False):
        score += 20
        
    # 5. Length Check (Risk: +10)
    if analysis.get("length_check", {}).get("risk_applied", False):
        score += 10
        
    # 6. Special Character Check (Risk: +10)
    if analysis.get("special_char_check", {}).get("risk_applied", False):
        score += 10

    # Cap score at 100
    risk_score = min(score, 100)
    
    # Determine risk level
    if risk_score <= 30:
        risk_level = "LOW"
    elif risk_score <= 60:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"
        
    return risk_score, risk_level
