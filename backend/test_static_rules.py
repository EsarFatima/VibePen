"""Automated tests for the VibePen Semgrep rules.

Each case writes one small file, scans it, and checks that the rule fires
on the bad code (expected=True) and stays quiet on the safe code (expected=False).
Run from the backend folder:  python -m pytest test_static_rules.py -v
"""
import pytest

from detector.static_analyzer import analyze_directory

CASES = [
    # (name, file name, file content, rule id, should it be flagged?)
    ("openai key written in code", "config.js",
     'const openaiKey = "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE1234";',
     "detect-vibe-openai-keys", True),
    ("openai key read from environment", "config.js",
     "const openaiKey = process.env.OPENAI_API_KEY;",
     "detect-vibe-openai-keys", False),

    ("generic api key written in code", "client.js",
     'const apiKey = "abcd1234efgh5678ijkl";',
     "detect-hardcoded-generic-api-key", True),
    ("api key read from environment", "client.js",
     "const apiKey = process.env.API_KEY;",
     "detect-hardcoded-generic-api-key", False),

    ("password written in code", "db.js",
     'const password = "SuperSecret123";',
     "detect-hardcoded-password", True),
    ("password read from environment", "db.js",
     "const password = process.env.DB_PASSWORD;",
     "detect-hardcoded-password", False),

    ("service role key in public VITE variable", "supabase.js",
     "const key = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;",
     "vibepen-secret-in-public-env", True),
    ("normal public VITE variable", "api.js",
     "const url = import.meta.env.VITE_API_URL;",
     "vibepen-secret-in-public-env", False),

    ("database open to everyone", "firestore.rules",
     "allow read, write: if true;",
     "vibepen-open-database", True),
    ("database requires login", "firestore.rules",
     "allow read, write: if request.auth != null;",
     "vibepen-open-database", False),
]


@pytest.mark.parametrize("name,filename,content,rule,expected", CASES, ids=[c[0] for c in CASES])
def test_rule(tmp_path, name, filename, content, rule, expected):
    (tmp_path / filename).write_text(content, encoding="utf-8")
    findings = analyze_directory(str(tmp_path))
    assert not any("error" in f for f in findings), findings
    flagged = rule in {f["type"] for f in findings}
    assert flagged == expected