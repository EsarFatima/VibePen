#!/usr/bin/env python3
"""
Test injection checks at all DVWA security levels for evaluation.
"""

from detector.dynamic.run_dynamic_injection import run_injection_checks

def test_all_levels():
    results = {}
    for level in ['low', 'medium', 'high', 'impossible']:
        print(f'\n=== Testing at SECURITY LEVEL: {level.upper()} ===')
        try:
            findings = run_injection_checks(security_level=level)
            results[level] = findings
            print(f'Total findings: {len(findings)}')
            for finding in findings:
                print(f'  - {finding.get("type", "unknown")}: {finding.get("evidence", str(finding)[:60])}')
        except Exception as e:
            print(f'Error: {e}')
            results[level] = []
    
    # Print summary table
    print("\n" + "="*80)
    print("EVALUATION SUMMARY TABLE")
    print("="*80)
    
    sql_error = []
    sql_bool = []
    xss_reflected = []
    
    for level in ['low', 'medium', 'high', 'impossible']:
        findings = results[level]
        sql_error.append('✅' if any('sql_injection' in f.get('type', '') for f in findings) else '❌')
        sql_bool.append('✅' if any('sql_injection' in f.get('type', '') for f in findings) else '❌')
        xss_reflected.append('✅' if any('xss_risk' in f.get('type', '') for f in findings) else '❌')
    
    print(f"| {'Security Level':<18} | {'SQLi (error-based)':<20} | {'SQLi (boolean-based)':<20} | {'Reflected XSS':<15} |")
    print(f"|{'-'*18}|{'-'*20}|{'-'*20}|{'-'*15}|")
    for i, level in enumerate(['low', 'medium', 'high', 'impossible']):
        print(f"| {level:<18} | {sql_error[i]:<20} | {sql_bool[i]:<20} | {xss_reflected[i]:<15} |")

if __name__ == "__main__":
    test_all_levels()
