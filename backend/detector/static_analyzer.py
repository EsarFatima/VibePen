import esprima

def analyze_js(code: str, filename: str = "unknown.js"):
    findings = []
    try:
        esprima.parseScript(code, tolerant=True)
    except Exception as e:
        return [{"error": f"parse failed: {e}"}]

    if "eval(" in code:
        findings.append({
            "type": "unsafe_eval",
            "evidence": "eval( usage detected",
            "location": filename
        })

    if "innerHTML" in code and "sanitize" not in code:
        findings.append({
            "type": "xss_risk",
            "evidence": "innerHTML assignment without visible sanitization",
            "location": filename
        })

    return findings

if __name__ == "__main__":
    sample = 'function f(x) { eval(x); document.body.innerHTML = x; }'
    print(analyze_js(sample))