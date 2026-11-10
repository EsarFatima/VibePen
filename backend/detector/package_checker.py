import json
import os
import sys
import urllib.parse

import requests

SKIP_DIRS = {"node_modules", ".git", "dist", "build"}
# Versions that point somewhere other than the npm registry - we can't check these
NON_REGISTRY = ("file:", "link:", "git", "http", "workspace:", "npm:", "github:")
MAX_PACKAGES = 300


def find_package_jsons(directory):
    found = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if "package.json" in files:
            found.append(os.path.join(root, "package.json"))
    return found


def package_exists(name):
    """True = on npm, False = npm says it does not exist, None = could not tell (e.g. no internet)."""
    url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    try:
        response = requests.get(url, timeout=8, headers={"Accept": "application/vnd.npm.install-v1+json"})
    except requests.RequestException:
        return None
    if response.status_code == 200:
        return True
    if response.status_code == 404:
        return False
    return None


def check_packages(directory):
    findings = []
    checked = set()

    for path in find_package_jsons(directory):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            continue

        relative = os.path.relpath(path, directory)
        dependencies = {}
        dependencies.update(data.get("dependencies") or {})
        dependencies.update(data.get("devDependencies") or {})

        for name, version in dependencies.items():
            if name in checked or len(checked) >= MAX_PACKAGES:
                continue
            checked.add(name)
            if str(version).startswith(NON_REGISTRY):
                continue
            if package_exists(name) is False:
                findings.append({
                    "type": "vibepen-nonexistent-package",
                    "title": "vibepen-nonexistent-package",
                    "evidence": f'"{name}": "{version}"',
                    "location": f"{relative} (dependencies)",
                    "severity": "ERROR",
                    "message": f'The package "{name}" does not exist on npm. AI tools sometimes invent package names.',
                    "description": f'The package "{name}" does not exist on npm.',
                })
    return findings


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "."
    results = check_packages(folder)
    print(f"Found {len(results)} package problem(s)")
    for item in results:
        print(" -", item["evidence"], "in", item["location"])