import hashlib
from collections import Counter


SCORING_RULES = {
    "missing_auth": {
        "severity": "critical",
        "confidence": 0.98,
        "title": "Private information is visible without signing in",
        "description": "Someone who is not signed in was able to open an area that should be private.",
        "remediation": "Require sign-in and check the person’s permissions before showing private information.",
    },
    "broken_access_control": {
        "severity": "critical",
        "confidence": 0.95,
        "title": "One account can view another account’s private information",
        "description": "A signed-in account was able to open another account’s basket or private resource.",
        "remediation": "Check that the signed-in account owns the requested resource before returning it.",
    },
    "sql_injection_pattern": {
        "severity": "high",
        "confidence": 0.85,
        "title": "A search or form may accept harmful instructions",
        "description": "Specially crafted text changed the response in a way that may let someone interfere with stored data.",
        "remediation": "Treat form values as data only and safely separate them from database commands.",
    },
    "xss_risk": {
        "severity": "high",
        "confidence": 0.7,
        "title": "User input may run as unwanted code",
        "description": "Text entered by a user was returned by the site without enough protection.",
        "remediation": "Clean and safely format user-entered text before displaying it to other people.",
    },
    "wildcard_cors": {
        "severity": "medium",
        "confidence": 0.95,
        "title": "The site accepts requests from any website",
        "description": "Another website may be allowed to ask this site for information.",
        "remediation": "Allow requests only from websites that you trust.",
    },
    "verbose_error_handling": {
        "severity": "low",
        "confidence": 0.8,
        "title": "Error messages reveal too much detail",
        "description": "An unusual request caused the site to reveal details about how it works.",
        "remediation": "Show visitors a simple error message and keep technical details in private server logs.",
    },
    "missing_security_headers": {
        "severity": "low",
        "confidence": 0.95,
        "title": "Some browser safety settings are missing",
        "description": "The website does not tell browsers to apply several helpful safety restrictions.",
        "remediation": "Add a Content Security Policy, Referrer Policy, and Permissions Policy appropriate for the application.",
    },
    "insecure_transport": {
        "severity": "high",
        "confidence": 0.99,
        "title": "The website connection is not protected",
        "description": "The website is using an unencrypted connection that could be observed or changed in transit.",
        "remediation": "Use HTTPS for the website and redirect HTTP traffic to the secure address.",
    },
}

SEVERITY_POINTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}

SCORING_RULES.update({
    "vibepen-open-database": {
        "severity": "critical",
        "confidence": 0.9,
        "title": "Your database is open to everyone",
        "description": "The database rules let anyone on the internet read or change your data without logging in.",
        "remediation": "Change the rules so only signed-in users can access data, and only their own data.",
    },
    "vibepen-secret-in-public-env": {
        "severity": "critical",
        "confidence": 0.85,
        "title": "A secret key is visible to every visitor",
        "description": "A private key is stored in a setting that gets sent to the browser, so anyone can open the page source and copy it.",
        "remediation": "Move the key to the server side (without the VITE_ / NEXT_PUBLIC_ / REACT_APP_ prefix) and rotate the old key.",
    },
    "detect-vibe-openai-keys": {
        "severity": "critical",
        "confidence": 0.9,
        "title": "An OpenAI key is written in the code",
        "description": "Anyone who sees this code can use your OpenAI account and you pay the bill.",
        "remediation": "Delete the key from the code, create a new one, and keep it in a private environment variable on the server.",
    },
    "detect-hardcoded-generic-api-key": {
        "severity": "high",
        "confidence": 0.6,
        "title": "An API key is written in the code",
        "description": "A key or token is typed directly in the code. If the code is shared or public, others can use it.",
        "remediation": "Move the key into a private environment variable and rotate it if the code was ever shared.",
    },
    "detect-hardcoded-password": {
        "severity": "medium",
        "confidence": 0.6,
        "title": "A password is written in the code",
        "description": "A password is typed directly in the code, so anyone who can read the code can see it.",
        "remediation": "Move the password into a private environment variable or a secrets store.",
    },
})


def _finding_id(finding: dict) -> str:
    identity = f"{finding.get('type', 'unknown')}|{finding.get('location', '')}|{finding.get('evidence', '')}"
    return hashlib.sha1(identity.encode("utf-8")).hexdigest()[:12]


def score_finding(finding: dict) -> dict:
    result = dict(finding)
    rule = SCORING_RULES.get(finding.get("type"), {
        "severity": "info",
        "confidence": 0.4,
        "title": "Unclassified scanner result",
        "description": "The scanner produced a result without a configured scoring rule.",
        "remediation": None,
    })
    result.update({
        "id": _finding_id(finding),
        "severity": rule["severity"],
        "confidence": rule["confidence"],
        "title": rule["title"],
        "description": rule["description"],
        "remediation": rule["remediation"],
        "score": round(SEVERITY_POINTS[rule["severity"]] * rule["confidence"], 2),
    })
    return result


def score_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        (score_finding(finding) for finding in findings if "error" not in finding),
        key=lambda item: item["score"],
        reverse=True,
    )


def build_scan_report(target: str, findings: list[dict]) -> dict:
    scored_findings = score_findings(findings)
    severities = Counter(item["severity"] for item in scored_findings)
    return {
        "target": target,
        "total_findings": len(scored_findings),
        "severity_counts": dict(severities),
        "risk_score": round(sum(item["score"] for item in scored_findings), 2),
        "findings": scored_findings,
    }



SCORING_RULES["vibepen-nonexistent-package"] = {
    "severity": "high",
    "confidence": 0.85,
    "title": "Your app uses a package that does not exist",
    "description": "This package name is not on npm. AI tools sometimes invent package names, and an attacker can register that name and hide harmful code in it, which then gets installed in your app.",
    "remediation": "Remove it or replace it with the real package you meant, and double-check the spelling before running npm install.",
}