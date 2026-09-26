import subprocess
import json
import os

def analyze_directory(target_directory: str):
    """
    Scans a project directory using custom Semgrep rules.
    This replaces the basic esprima string check to meet FYP scope requirements.
    """
    # Use the absolute path to the rules file inside the detector folder
    current_dir = os.path.dirname(os.path.abspath(__file__))
    rule_path = os.path.join(current_dir, "rules.yaml")
    
    # Initialize an empty findings array to return to FastAPI
    formatted_findings = []
    
    # Verify that the custom rule configuration file exists
    if not os.path.exists(rule_path):
        return [{"error": f"Configuration file missing at {rule_path}"}]
        
    print(f"[*] VibePen Engine running static analysis on: {target_directory}")
    
    # Execute Semgrep directly and request structured JSON output
    command = ["semgrep", "scan", f"--config={rule_path}", target_directory, "--json"]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=False)

        
        # If Semgrep outputs a clean payload, parse it
        if result.stdout.strip():
            scan_data = json.loads(result.stdout)
            raw_results = scan_data.get("results", [])
            
            for match in raw_results:
                formatted_findings.append({
                    "type": match.get("check_id", "vulnerability_detected"),
                    "evidence": match.get("extra", {}).get("lines", "").strip(),
                    "location": f"{match.get('path')} (Line {match.get('start', {}).get('line')})",
                    "severity": match.get("extra", {}).get("severity", "ERROR"),
                    "message": match.get("extra", {}).get("message", "")
                })
                
        return formatted_findings

    except json.JSONDecodeError:
        return [{"error": "Failed to parse backend scanning JSON matrix."}]
    except Exception as e:
        return [{"error": f"Scanner runtime error: {str(e)}"}]

if __name__ == "__main__":
    # Create a tiny test file path locally to verify the module independently
    current_dir = os.path.dirname(os.path.abspath(__file__))
    print("[*] Running local module self-test...")
    print(analyze_directory(current_dir))
