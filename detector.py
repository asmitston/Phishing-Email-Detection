import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = {
    "urgent": 1,
    "verify your account": 2,
    "account suspended": 2,
    "click here": 1,
    "password": 1,
    "immediately": 1,
    "24 hours": 1,
    "confirm your identity": 2,
    "update your payment": 2,
    "security alert": 1,
    "permanent suspension": 2
}

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com"
}


def analyze_email(sender, subject, body):

    findings = []
    score = 0

    email_text = f"{subject} {body}".lower()

    # 1. Suspicious keyword detection
    for keyword, points in SUSPICIOUS_KEYWORDS.items():
        if keyword in email_text:
            score += points
            findings.append(
                f"Suspicious phrase detected: {keyword}"
            )

    # 2. Sender email analysis
    sender = sender.strip().lower()

    if "@" not in sender:
        score += 2
        findings.append("Invalid sender email address")
    else:
        sender_domain = sender.rsplit("@", 1)[1]

        for brand, official_domain in BRAND_DOMAINS.items():
            if brand in sender_domain:
                if sender_domain != official_domain:
                    if not sender_domain.endswith(
                        "." + official_domain
                    ):
                        score += 3
                        findings.append(
                            f"Possible impersonation of {brand}"
                        )

    # 3. Extract URLs
    urls = re.findall(
        r'https?://[^\s<>"\']+',
        body,
        flags=re.IGNORECASE
    )

    # 4. URL security analysis
    for url in urls:

        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()

        if parsed.scheme.lower() == "http":
            score += 1
            findings.append(
                f"Unencrypted HTTP URL: {url}"
            )

        if "@" in parsed.netloc:
            score += 2
            findings.append(
                "URL contains @ symbol"
            )

        for brand, official_domain in BRAND_DOMAINS.items():

            if brand in domain:
                if domain != official_domain:
                    if not domain.endswith(
                        "." + official_domain
                    ):
                        score += 3
                        findings.append(
                            f"Possible fake {brand} URL: {url}"
                        )

    # 5. Final classification
    if score >= 7:
        risk_level = "HIGH RISK"
        result = "Potential Phishing Email"

    elif score >= 3:
        risk_level = "MEDIUM RISK"
        result = "Suspicious Email"

    else:
        risk_level = "LOW RISK"
        result = "No Strong Phishing Indicators Detected"

    return {
        "score": score,
        "risk_level": risk_level,
        "result": result,
        "findings": findings,
        "urls": urls
    }