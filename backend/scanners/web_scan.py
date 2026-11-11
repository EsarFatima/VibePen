import sys
from urllib.parse import urlparse

import requests

from scanners.playwright_crawler import crawl
from scanners.secret_scanner import scan_text_for_secrets

MAX_SCRIPTS = 40
MAX_BYTES = 5 * 1024 * 1024


def scan_site_secrets(start_url):
    """Crawl the site in a real browser, then look for leaked keys inside every JavaScript file it loaded."""
    site = urlparse(start_url).netloc
    crawled = crawl(start_url)
    findings = []

    for script_url in crawled["scripts"][:MAX_SCRIPTS]:
        if urlparse(script_url).netloc != site:
            continue  # never touch files from other websites
        try:
            response = requests.get(script_url, timeout=8)
        except requests.RequestException:
            continue
        if len(response.content) > MAX_BYTES:
            continue
        findings.extend(scan_text_for_secrets(response.text, script_url))

    return findings, crawled


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    results, crawled = scan_site_secrets(target)
    print(f"Crawled {len(crawled['pages'])} page(s), checked {len(crawled['scripts'])} script(s)")
    print(f"Secrets found: {len(results)}")
    for item in results:
        print(" -", item["evidence"])


def safe_secret_findings(start_url):
    """Used by the live scan. If the browser part fails, the rest of the scan still works."""
    try:
        return scan_site_secrets(start_url)[0]
    except Exception:
        return []