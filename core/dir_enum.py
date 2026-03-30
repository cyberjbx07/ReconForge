"""
Module: Directory Enumeration
Description: Finds hidden directories + analyzes responses
Author: CyberJBX
"""

import requests
from concurrent.futures import ThreadPoolExecutor

def scan_directory(target, d):
    """
    Scan a single directory endpoint.

    Args:
        target (str): Target domain
        d (str): Directory name from wordlist

    Returns:
        dict | None: Returns result dictionary if found, else None
    """

    # ==========================
    # BUILD TARGET URL
    # ==========================
    url = f"https://{target}/{d}"

    # ==========================
    # INITIALIZE VARIABLES
    # ==========================
    tech_stack = []
    missing_headers = []

    try:
        # ==========================
        # SEND HTTP REQUEST
        # ==========================
        response = requests.get(url, timeout=3)

        # ==========================
        # CHECK VALID RESPONSE
        # ==========================
        if response.status_code in [200, 301, 302, 403]:

            # ==========================
            # BASIC RESPONSE INFO
            # ==========================
            size = len(response.text)
            server = response.headers.get("Server", "Unknown")

            # ==========================
            # TECHNOLOGY DETECTION
            # ==========================
            x_powered = response.headers.get("X-Powered-By", "")
            content = response.text.lower()

            if "PHP" in x_powered:
                tech_stack.append("PHP")

            if "cloudflare" in server.lower():
                tech_stack.append("Cloudflare")

            if "wp-content" in content:
                tech_stack.append("WordPress")

            if "react" in content:
                tech_stack.append("React")

            if "jquery" in content:
                tech_stack.append("jQuery")

            # ==========================
            # SECURITY HEADER CHECK
            # ==========================
            security_headers = [
                "X-Frame-Options",
                "Content-Security-Policy",
                "X-XSS-Protection",
                "Strict-Transport-Security"
            ]

            for h in security_headers:
                if h not in response.headers:
                    missing_headers.append(h)

            # ==========================
            # RETURN RESULT
            # ==========================
            return {
                "path": f"/{d}",
                "status": response.status_code,
                "size": size,
                "server": server,
                "tech": tech_stack,
                "missing_headers": missing_headers
            }

    except requests.RequestException:
        # Ignore connection errors / timeouts
        return None
    
    
def run_dir_enum(target, mode="fast"):
    """Run directory enumeration with response analysis"""

    found_dirs = []

    print(f"\n[+] Running Directory Enumeration on {target}")

    # ==========================
    # LOAD WORDLIST
    # ==========================
    if mode == "fast":
        wordlist_file = "data/dirs_small.txt"
    else:
        wordlist_file = "data/dirs.txt"
    try:
        with open(wordlist_file, "r") as f:
            dirs = f.read().splitlines()
    except FileNotFoundError:
        print("[-] Wordlist not found")
        return []

    # ==========================
    # ENUMERATION LOGIC
    # ==========================
    found_dirs = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(lambda d: scan_directory(target, d), dirs)

    for result in results:
        if result:
            found_dirs.append(result)
    
    print("\n[INFO]========== DIRECTORY RESULTS ==========\n")

    for d in found_dirs:
        print(f"[FOUND] {d['path']} → {d['status']} | size: {d['size']} | server: {d['server']}")

        # Tech
        if d["tech"]:
            print("  Tech Detected:")
            for t in d["tech"]:
                print(f"   - {t}")
        else:
            print("  Tech Detected: None")

        # Headers
        if d["missing_headers"]:
            print("  Missing Headers:")
            for h in d["missing_headers"]:
                print(f"   - {h}")
        else:
            print("  Missing Headers: None")

        print("-" * 40)


    # ==========================
    # AFTER LOOP ONLY
    # ==========================
    if not found_dirs:
        print("[INFO] No directories found")

    return found_dirs