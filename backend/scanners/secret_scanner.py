"""
VibePen Secret Scanner Module (Tool 2.4 — The Credential Finder).

Finds credentials, API keys, and sensitive tokens exposed in:
1. Target webpage HTML and inline <script> tags.
2. Downloaded external JavaScript bundles (e.g. main.js, scripts.js, runtime.js).

Targeted patterns:
- AWS Access Keys
- OpenAI API Keys
- Stripe API Keys (Live & Test)
- Google Cloud / Firebase API Keys
- GitHub Personal Access Tokens
- Slack Webhook URLs and Bot Tokens
- Generic Hardcoded Password/Secret Assignments
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import requests

# Compiled regex patterns for known high-risk API keys and credentials
SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "confidence": 0.98,
        "description": "Exposed Amazon Web Services (AWS) Access Key ID."
    },
    {
        "name": "OpenAI API Key",
        "pattern": re.compile(r"\b(sk-[a-zA-Z0-9_\-]{20,}|sk-proj-[a-zA-Z0-9_\-]{20,})\b"),
        "confidence": 0.95,
        "description": "Exposed OpenAI API Secret Key."
    },
    {
        "name": "Stripe API Key",
        "pattern": re.compile(r"\b([rs]k_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
        "confidence": 0.96,
        "description": "Exposed Stripe payment processing secret/restricted key."
    },
    {
        "name": "Google / Firebase API Key",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "confidence": 0.92,
        "description": "Exposed Google Cloud / Firebase API Key."
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{36,})\b"),
        "confidence": 0.98,
        "description": "Exposed GitHub Personal Access or OAuth Token."
    },
    {
        "name": "Slack Webhook URL",
        "pattern": re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+)"),
        "confidence": 0.95,
        "description": "Exposed Slack incoming webhook URL."
    },
    {
        "name": "Generic Hardcoded Secret Assignment",
        "pattern": re.compile(
            r"""(?i)(?:api_key|apikey|secret|password|access_token|client_secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-!@#$%^&*]{10,})['"]"""
        ),
        "confidence": 0.85,
        "description": "Hardcoded credential or secret assignment variable."
    }
]

# Patterns to filter out obvious false positives (e.g. dummy placeholders or common framework identifiers)
IGNORE_STRINGS = {
    "undefined", "null", "placeholder", "your_api_key", "your_secret",
    "password123", "changeme", "example", "mysecretkey", "000000000000"
}


def mask_secret(secret: str) -> str:
    """Masks secret so it is safely displayed in reports without full disclosure."""
    if len(secret) <= 8:
        return secret[:2] + "****" + secret[-2:]
    return secret[:4] + "..." + secret[-4:]


def extract_script_urls(html_content: str, base_url: str) -> List[str]:
    """Extracts all external JavaScript URLs from <script src="..."> tags."""
    soup = BeautifulSoup(html_content, "html.parser")
    script_urls: List[str] = []
    seen: Set[str] = set()

    for script_tag in soup.find_all("script"):
        src = script_tag.get("src")
        if not src:
            continue
        full_url = urljoin(base_url, src)
        parsed = urlparse(full_url)
        # Avoid non-http schemes (e.g. data:, blob:)
        if parsed.scheme in ("http", "https") and full_url not in seen:
            seen.add(full_url)
            script_urls.append(full_url)

    return script_urls


def scan_text_for_secrets(content: str, source_label: str) -> List[Dict[str, Any]]:
    """Scans raw text content (HTML or JS) against secret patterns."""
    findings: List[Dict[str, Any]] = []
    seen_matches: Set[str] = set()

    for rule in SECRET_PATTERNS:
        for match in rule["pattern"].finditer(content):
            # Group 1 captures the key/token
            token = match.group(1) if match.groups() else match.group(0)

            # Skip common test placeholders or false positives
            if token.lower() in IGNORE_STRINGS or len(token.strip()) < 8:
                continue

            unique_key = f"{rule['name']}|{token}"
            if unique_key in seen_matches:
                continue
            seen_matches.add(unique_key)

            masked = mask_secret(token)
            findings.append({
                "type": "hardcoded_secret",
                "evidence": f"Found {rule['name']} ({masked}) in {source_label}",
                "location": source_label,
                "rule_name": rule["name"],
                "description": rule["description"]
            })

    return findings


def scan_target_secrets(target_url: str, max_scripts: int = 8) -> List[Dict[str, Any]]:
    """
    Main entry point:
    1. Downloads the target web page HTML.
    2. Scans inline HTML & scripts.
    3. Discovers and downloads linked JavaScript bundles.
    4. Scans each bundle for exposed secrets.
    """
    findings: List[Dict[str, Any]] = []
    session = requests.Session()
    session.headers.update({"User-Agent": "VibePen-Security-Scanner/1.0"})

    try:
        root_resp = session.get(target_url, timeout=5)
        html_text = root_resp.text
    except requests.RequestException:
        # If target is unreachable, return empty findings gracefully
        return []

    # 1. Scan root HTML (including inline scripts)
    findings.extend(scan_text_for_secrets(html_text, f"{target_url} (HTML/inline)"))

    # 2. Extract script bundles
    script_urls = extract_script_urls(html_text, target_url)

    # 3. Download and inspect each script bundle (capped at max_scripts for performance)
    for script_url in script_urls[:max_scripts]:
        try:
            js_resp = session.get(script_url, timeout=5)
            # Only analyze text/javascript or readable code files under 5MB
            if len(js_resp.content) > 5 * 1024 * 1024:
                continue
            findings.extend(scan_text_for_secrets(js_resp.text, script_url))
        except requests.RequestException:
            continue

    return findings
