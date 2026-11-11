import sys
from urllib.parse import urldefrag, urlparse

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # machines without Playwright installed skip the crawler
    sync_playwright = None

MAX_PAGES = 10
PAGE_TIMEOUT_MS = 15000


def clean(url):
    """Same page = same address. Keeps app routes like /#/login, drops other # parts."""
    base, fragment = urldefrag(url)
    base = base.rstrip("/")
    return f"{base}/#{fragment}" if fragment.startswith("/") else base


def crawl(start_url, max_pages=MAX_PAGES):
    """Open the site in a real browser and collect pages, forms, scripts and background requests.
    It never leaves the site it was given."""
    site = urlparse(start_url).netloc
    to_visit = [clean(start_url)]
    visited = set()
    result = {"pages": [], "forms": [], "scripts": set(), "api_calls": set()}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()

        def stay_on_site(route):
            request = route.request
            # Block the browser from navigating to any other website
            if request.resource_type == "document" and urlparse(request.url).netloc != site:
                route.abort()
            else:
                route.continue_()

        context.route("**/*", stay_on_site)
        page = context.new_page()

        def on_response(response):
            if urlparse(response.url).netloc != site:
                return  # only record things that belong to the site being scanned
            request = response.request
            if request.resource_type == "script":
                result["scripts"].add(response.url)
            elif request.resource_type in ("fetch", "xhr"):
                result["api_calls"].add(f"{request.method} {response.url} -> {response.status}")

        page.on("response", on_response)

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                page.goto(url, wait_until="load", timeout=PAGE_TIMEOUT_MS)
                page.wait_for_timeout(1500)  # give React/Angular pages time to build themselves
            except Exception as error:
                result["pages"].append({"url": url, "error": "skipped: " + str(error)[:60]})
                continue

            if urlparse(page.url).netloc != site:
                result["pages"].append({"url": url, "error": "skipped: redirected to another website"})
                continue

            result["pages"].append({"url": url, "title": page.title()})

            forms = page.evaluate("""() => [...document.forms].map(f => ({
                action: f.action,
                method: f.method,
                inputs: [...f.elements].filter(e => e.name).map(e => e.name + ':' + e.type)
            }))""")
            for form in forms:
                form["page"] = url
                result["forms"].append(form)

            links = page.evaluate("() => [...document.querySelectorAll('a[href]')].map(a => a.href)")
            for link in links:
                parsed = urlparse(link)
                link = clean(link)
                if parsed.scheme in ("http", "https") and parsed.netloc == site and link not in visited:
                    to_visit.append(link)

        browser.close()

    result["scripts"] = sorted(result["scripts"])
    result["api_calls"] = sorted(result["api_calls"])
    return result


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    found = crawl(target)
    print(f"\nPages visited: {len(found['pages'])}")
    for item in found["pages"]:
        print("  -", item["url"], "|", item.get("title") or item.get("error"))
    print(f"\nForms found: {len(found['forms'])}")
    for form in found["forms"]:
        print("  -", form["method"].upper(), form["action"], form["inputs"])
    print(f"\nJavaScript files: {len(found['scripts'])}")
    for script in found["scripts"]:
        print("  -", script)
    print(f"\nBackground requests: {len(found['api_calls'])}")
    for call in found["api_calls"]:
        print("  -", call)