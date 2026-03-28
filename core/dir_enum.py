"""
Module: Directory Enumeration
Description: Finds hidden directories + analyzes responses
Author: CyberJBX
"""

import requests


def run_dir_enum(target):
    """Run directory enumeration with response analysis"""

    found_dirs = []

    print(f"\n[+] Running Directory Enumeration on {target}")

    # ==========================
    # LOAD WORDLIST
    # ==========================
    try:
        with open("data/dirs.txt", "r") as f:
            dirs = f.read().splitlines()
    except FileNotFoundError:
        print("[-] Wordlist not found")
        return []

    # ==========================
    # ENUMERATION LOGIC
    # ==========================
    for d in dirs:
        url = f"https://{target}/{d}"

        try:
            response = requests.get(url, timeout=3)

            # ==========================
            # VALID STATUS CHECK
            # ==========================
            if response.status_code in [200, 301, 302, 403]:

                # ==========================
                # RESPONSE ANALYSIS
                # ==========================
                size = len(response.text)
                server = response.headers.get("Server", "Unknown")

                print(f"[FOUND] /{d} → {response.status_code} | size: {size} | server: {server}")

                found_dirs.append({
                    "path": f"/{d}",
                    "status": response.status_code,
                    "size": size,
                    "server": server
                })

        except requests.RequestException:
            pass

    return found_dirs