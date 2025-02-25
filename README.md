# Email_analysis
Project Overview
Fake email detection is a cybersecurity tool that analyzes email headers, sender details, and email content to determine whether an email is genuine, suspicious, or phishing. The goal is to protect users from phishing attacks, email spoofing, and fraud.

This project helps detect fake or malicious emails by checking:
✅ Sender authenticity (MX records, SPF verification)
✅ Phishing keywords in the email body
✅ Suspicious URLs linked to phishing sites
✅ Domain reputation (disposable & newly registered domains)

🛠 How It Works? (Step-by-Step)
Step 1: Extract Email Data
📩 Reads email headers & body from an .eml file.
📬 Extracts From, To, Subject, SPF, and Return-Path.

Step 2: Check Sender Authenticity
✅ Validates sender’s domain using MX records.
🚫 Flags disposable emails and newly registered domains.

Step 3: Scan for Phishing Keywords
🔎 Looks for suspicious phrases in the email body.
⚠️ Flags common phishing terms (e.g., "urgent," "click here").

Step 4: Analyze URLs
🔗 Extracts all links from the email body.
🛑 Checks if the URLs exist in PhishTank (known phishing sites).

Step 5: Assign Risk Score & Generate Report
📊 Calculates a final risk score based on:

Domain validation ✅/❌
Phishing keywords ⚠️
Suspicious URLs 🚨
🔴 Final decision: Safe, Suspicious, or Phishing!
