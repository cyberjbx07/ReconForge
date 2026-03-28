"""
Module: Directory Enumeration
Description: Finds hidden directories using wordlist
Author: CyberJBX
"""

import requests


def run_dir_enum(target):
    """Run directory enumeration"""

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
        url = f"http://{target}/{d}"

        try:
            response = requests.get(url, timeout=3)

            # ==========================
            # VALID STATUS CHECK
            # ==========================
            if response.status_code in [200, 301, 302, 403]:
                print(f"[FOUND] /{d} → {response.status_code}")
                found_dirs.append({
                    "path": f"/{d}",
                    "status": response.status_code
                })

        except requests.RequestException:
            pass

    return found_dirs