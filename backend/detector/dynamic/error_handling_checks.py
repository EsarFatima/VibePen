import requests
import re


def check_verbose_error_handling(session: requests.Session, url: str, param: str, extra_params: dict = None) -> list[dict]:
    """
    Test if the app leaks technical details in error responses.
    
    Strategy:
    1. Send malformed/invalid input to the endpoint
    2. Capture the error response
    3. Search for technical leaks (DB errors, file paths, stack traces, versions)
    
    Examples of "malformed input":
    - SQL injection payload: ' OR '1'='1
    - Invalid JSON: {bad json}
    - Command injection: ; cat /etc/passwd
    - Path traversal: ../../../etc/passwd
    - Unicode/encoding issues
    """
    findings = []
    
    # Keywords that indicate information disclosure / verbose errors
    # These patterns indicate the server is leaking technical implementation details
    leak_patterns = {
        "traceback": "Python traceback/stack trace leaked",
        "sqlexception": "SQL exception details leaked",
        "error in your sql": "SQL syntax error details leaked",
        "warning: mysql": "MySQL-specific error details leaked",
        "syntax error": "Syntax error details leaked",
        "line ": "Line number/code location leaked",
        "/home/": "File path leaked (Linux home directory)",
        "/var/": "File path leaked (Linux /var directory)",
        "/usr/": "File path leaked (Linux /usr directory)",
        "/etc/": "File path leaked (Linux /etc directory)",
        "apache/": "Server software and version leaked (Apache)",
        "nginx/": "Server software and version leaked (Nginx)",
        "iis/": "Server software and version leaked (IIS)",
        "mysql ": "Database software and version leaked (MySQL)",
        "postgresql": "Database software and version leaked (PostgreSQL)",
        "sqlite": "Database software and version leaked (SQLite)",
        "python ": "Programming language and version leaked (Python)",
        "node.js": "Programming language and version leaked (Node.js)",
        "php/": "Programming language and version leaked (PHP)",
        "java": "Programming language and version leaked (Java)",
        "stack trace": "Stack trace/debug information leaked",
        "exception": "Exception details leaked",
        "at line": "Code line number leaked",
        "file ": "File path or filename leaked",
    }
    
    # Test payloads designed to trigger errors
    # Each one should cause the app to generate an error response
    test_payloads = [
        "'",  # Single quote (SQL error)
        "' OR '1'='1",  # SQL injection
        "{broken}",  # Invalid JSON
        "'; DROP TABLE--",  # SQL injection comment-style
        "../../../etc/passwd",  # Path traversal
        "<script>alert('xss')</script>",  # XSS attempt
        "1; DROP TABLE users--",  # Numeric injection
        "%00",  # Null byte
        "\x00",  # Null character
    ]
    
    for payload in test_payloads:
        try:
            params = {param: payload}
            if extra_params:
                params.update(extra_params)
            
            resp = session.get(url, params=params, timeout=5)
            
            # Check if response contains leaked technical info
            response_text_lower = resp.text.lower()
            
            # Look for each leak pattern
            for pattern, description in leak_patterns.items():
                if pattern in response_text_lower:
                    findings.append({
                        "type": "verbose_error_handling",
                        "evidence": f"{description} when sending malformed input to param '{param}'",
                        "location": url,
                        "payload_used": payload[:50],  # Truncate for readability
                    })
                    break  # Found a leak for this payload, move to next
                    
        except requests.RequestException as e:
            findings.append({"error": f"request failed: {e}"})
    
    return findings


if __name__ == "__main__":
    from detector.dynamic.auth_session import login_dvwa, set_dvwa_security
    
    session = login_dvwa("http://localhost:8080", username="admin", password="password")
    set_dvwa_security(session, "http://localhost:8080", "low")
    
    # Test on DVWA's SQL injection page
    url = "http://localhost:8080/vulnerabilities/sqli/"
    extra = {"Submit": "Submit"}
    
    print("Testing for verbose error handling...")
    print(f"Target: {url}")
    results = check_verbose_error_handling(session, url, "id", extra)
    print(f"\nTotal findings: {len(results)}")
    for finding in results:
        print(f"  - {finding.get('type', 'unknown')}: {finding.get('evidence', str(finding)[:60])}")
