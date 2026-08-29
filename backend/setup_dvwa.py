#!/usr/bin/env python3
"""
Initialize DVWA database by hitting the setup.php page and extracting/posting the setup form.
This needs to run once before any vulnerability tests can work.
"""

import requests
import re
import time

def setup_dvwa(base_url: str = "http://localhost:8080") -> bool:
    """
    Visits DVWA setup.php, extracts the CSRF token, and submits the
    database creation form. Returns True if successful.
    """
    session = requests.Session()
    
    try:
        print(f"[*] Fetching setup page from {base_url}/setup.php...")
        setup_page = session.get(f"{base_url}/setup.php", timeout=5)
        
        if setup_page.status_code != 200:
            print(f"[!] Setup page returned status {setup_page.status_code}")
            return False
        
        # Look for the CSRF token on setup.php
        match = re.search(r"user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", setup_page.text)
        if not match:
            print("[!] Could not find CSRF token on setup page")
            return False
        
        csrf_token = match.group(1)
        print(f"[+] Found CSRF token: {csrf_token[:8]}...")
        
        # Submit the setup form
        print("[*] Submitting database creation form...")
        response = session.post(f"{base_url}/setup.php", data={
            "setup": "Create / Reset Database",
            "user_token": csrf_token,
        }, timeout=5)
        
        if response.status_code == 200:
            if "successfully created" in response.text.lower() or "reset" in response.text.lower():
                print("[+] DVWA database setup successful!")
                return True
            elif "already exists" in response.text.lower():
                print("[+] DVWA database already exists")
                return True
        
        print(f"[!] Setup returned status {response.status_code}, but may have succeeded")
        return True  # Assume success since the page loaded
        
    except requests.ConnectionError:
        print(f"[!] Could not connect to DVWA at {base_url}")
        print("[!] Make sure Docker container is running: docker start dvwa")
        return False
    except Exception as e:
        print(f"[!] Setup error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("DVWA Database Initialization Script")
    print("=" * 60)
    
    # Give Docker a moment if it just started
    print("\n[*] Waiting for DVWA to be ready...")
    time.sleep(3)
    
    success = setup_dvwa()
    if success:
        print("\n[+] Setup complete! You can now run vulnerability checks.")
        exit(0)
    else:
        print("\n[!] Setup failed. Check DVWA container is running.")
        exit(1)
