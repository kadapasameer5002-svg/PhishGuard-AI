import os
import logging
from groq import Groq
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_ai_explanation(url: str, risk_score: int, risk_level: str, detected_issues: list) -> str:
    """
    Calls the Groq API (Llama model) to generate a professional threat analysis.
    If the API call fails or the key is invalid, returns a rule-based fallback explanation.
    """
    api_key = os.getenv("GROQ_API_KEY")
    
    if not api_key or api_key.strip() == "":
        logger.warning("GROQ_API_KEY not found in environment. Using fallback explanation.")
        return get_fallback_explanation(url, risk_score, risk_level, detected_issues)
        
    try:
        # Initialize Groq client
        client = Groq(api_key=api_key.strip())
        
        # Format the user message with details
        issues_str = "\n".join([f"- {issue}" for issue in detected_issues]) if detected_issues else "- None detected"
        
        prompt = f"""You are a cybersecurity analyst. 
Explain the phishing risk of this URL.

URL: {url}
Risk Score: {risk_score}/100
Risk Level: {risk_level}
Detected Issues:
{issues_str}

Provide a professional, human-readable threat explanation, security impact, and recommendations. Keep it concise, authoritative, and direct. Do not use markdown headers like H1/H2, just write structured paragraphs or bullet points."""

        # Call Groq API
        # Using llama-3.1-8b-instant for fast response and reliability
        completion = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert security analyst specializing in URL analysis and phishing threat intelligence."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=500
        )
        
        ai_response = completion.choices[0].message.content.strip()
        if ai_response:
            return ai_response
            
    except Exception as e:
        logger.error(f"Error calling Groq API: {e}. Using fallback explanation.")
        
    return get_fallback_explanation(url, risk_score, risk_level, detected_issues)

def get_fallback_explanation(url: str, risk_score: int, risk_level: str, detected_issues: list) -> str:
    """
    Generates a high-quality fallback explanation if the AI service is unavailable.
    """
    if risk_level == "LOW":
        explanation = (
            f"The URL '{url}' exhibits low-risk characteristics with a risk score of {risk_score}/100. "
            "It appears to follow standard security conventions (such as utilizing HTTPS) and does not match "
            "any common automated phishing patterns or suspicious keywords. However, users should always practice "
            "standard security hygiene before entering credentials."
        )
    elif risk_level == "MEDIUM":
        issues_desc = ", ".join(detected_issues)
        explanation = (
            f"Caution: The URL '{url}' is classified as a MEDIUM risk ({risk_score}/100) due to the following indicators: "
            f"{issues_desc}. Phishing actors frequently employ minor deviations (such as omitting HTTPS, "
            "using long domains, or incorporating misleading keywords) to deceive targets. We recommend verifying the "
            "authenticity of this domain through secondary sources before submitting any sensitive details."
        )
    else:
        issues_desc = ", ".join(detected_issues)
        explanation = (
            f"WARNING: The URL '{url}' is classified as a HIGH risk ({risk_score}/100) and displays multiple suspicious indicators: "
            f"{issues_desc}. This configuration closely mimics phishing and credential-harvesting setups, "
            "such as the use of numeric IP addresses, suspicious high-risk Top-Level Domains (TLDs), or unauthorized brand "
            "keywords. Entering passwords, session tokens, or financial records on this platform is extremely risky."
        )
        
    return explanation
