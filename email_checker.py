import email
import re
import dns.resolver
import requests
import socket
import whois
from email import policy
from email.parser import BytesParser

# Define phishing keywords
PHISHING_KEYWORDS = [
    "urgent", "verify", "password reset", "click here", 
    "update account", "suspicious activity", "confirm your identity", "login immediately"
]

# List of known disposable email domains
DISPOSABLE_EMAIL_PROVIDERS = [
    "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com", "getnada.com"
]

def extract_email_headers(file_path):
    """Extracts email headers and body."""
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        headers = {
            "From": msg['From'] if msg['From'] else "Unknown",
            "To": msg['To'] if msg['To'] else "Unknown",
            "Subject": msg['Subject'] if msg['Subject'] else "No Subject",
            "Received-SPF": msg['Received-SPF'] if 'Received-SPF' in msg else "Unknown",
            "Return-Path": msg['Return-Path'] if 'Return-Path' in msg else "Unknown"
        }

        email_body = msg.get_body(preferencelist=('plain'))
        email_body = email_body.get_content() if email_body else ""

        return headers, email_body
    except Exception as e:
        print(f"❌ Error reading email file: {e}")
        return None, None

def validate_sender_domain(sender_email):
    """Checks if the sender's domain has a valid MX record."""
    try:
        domain = sender_email.split('@')[-1]

        # Check if domain is from a known disposable email provider
        if domain in DISPOSABLE_EMAIL_PROVIDERS:
            return False, "Disposable Email"

        # Check MX (Mail Exchange) records
        dns.resolver.resolve(domain, 'MX')
        
        # Check domain age (newly registered domains are often suspicious)
        domain_info = whois.whois(domain)
        if hasattr(domain_info, 'creation_date'):
            domain_age = (domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date)
            if domain_age and (2024 - domain_age.year) < 1:  # Less than 1 year old domain
                return False, "Newly Registered Domain"

        return True, "Valid Domain"
    except Exception:
        return False, "Invalid Domain"

def check_spf(headers):
    """Analyzes SPF record in headers."""
    return "pass" in headers.get("Received-SPF", "").lower()

def check_phishing_keywords(email_body):
    """Scans for phishing keywords."""
    email_body = email_body.lower()
    flagged_words = [word for word in PHISHING_KEYWORDS if word in email_body]
    return flagged_words

def extract_urls(email_body):
    """Extracts URLs from the email body."""
    url_pattern = r"https?://[^\s\"'<>]+"  
    urls = re.findall(url_pattern, email_body)
    return urls

def check_url_in_phishtank(url):
    """Checks if a URL is flagged as phishing in PhishTank."""
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(f"https://www.phishtank.com/checkurl/?url={url}", headers=headers, timeout=5)
        return "valid" in response.text.lower()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error checking URL in PhishTank: {e}")
        return None

def analyze_email(file_path):
    """Performs a full phishing risk assessment."""
    headers, email_body = extract_email_headers(file_path)
    if not headers:
        return

    risk_score = 0  

    # Sender Domain Validation
    sender_email = headers["From"].split()[-1].strip("<>")
    domain_valid, domain_status = validate_sender_domain(sender_email)
    if not domain_valid:
        risk_score += 4 if domain_status == "Newly Registered Domain" else 5  # Higher risk for invalid domain

    # SPF Check (Spoofing Protection)
    spf_valid = check_spf(headers)
    if not spf_valid:
        risk_score += 3  

    # Phishing Keywords Detection
    flagged_keywords = check_phishing_keywords(email_body)
    risk_score += len(flagged_keywords)  

    # URL Phishing Detection
    urls = extract_urls(email_body)
    phishing_urls = []
    for url in urls:
        is_phishing = check_url_in_phishtank(url)
        if is_phishing:
            phishing_urls.append(url)
            risk_score += 5  
        elif is_phishing is None:
            risk_score += 1  

    # **Final Report**
    print("\n📩 **Email Analysis Report**")
    print("="*50)
    print(f"📨 **From:** {headers['From']}")
    print(f"📬 **To:** {headers['To']}")
    print(f"📝 **Subject:** {headers['Subject']}")
    print(f"✅ **Sender Domain Valid:** {'Yes' if domain_valid else '❌ No (' + domain_status + ')'}")
    print(f"✅ **SPF Check Passed:** {'Yes' if spf_valid else '❌ No (Possible Spoofing)'}")

    if flagged_keywords:
        print(f"⚠️ **Suspicious Keywords Found:** {flagged_keywords}")

    if urls:
        print("\n🔗 **Extracted URLs:**")
        for url in urls:
            print(f" - {url} {'🚨 Phishing Detected!' if url in phishing_urls else '✅ Safe'}")

    print("\n🔍 **Final Email Risk Score:**", risk_score, "/ 15")

    # **Final Verdict**
    if risk_score >= 10:
        print("🚨 **Final Verdict: HIGH RISK (Phishing!)**")
    elif risk_score >= 6:
        print("⚠️ **Final Verdict: SUSPICIOUS (Be Cautious!)**")
    else:
        print("✅ **Final Verdict: SAFE EMAIL**")

    print("="*50)

# Example Usage
analyze_email(input())
