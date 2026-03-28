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
        missing_headers = []

        try:
            response = requests.get(url, timeout=3)

            if response.status_code in [200, 301, 302, 403]:

                # ==========================
                # RESPONSE ANALYSIS
                # ==========================
                size = len(response.text)
                server = response.headers.get("Server", "Unknown")

                # ==========================
                # TECHNOLOGY DETECTION
                # ==========================
                tech_stack = []

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
                # PRINT + STORE
                # ==========================
                print(f"[FOUND] /{d} → {response.status_code} | size: {size} | server: {server}")

                found_dirs.append({
                    "path": f"/{d}",
                    "status": response.status_code,
                    "size": size,
                    "server": server,
                    "missing_headers": missing_headers,
                    "tech": tech_stack
                })

        except requests.RequestException:
            pass

    return found_dirs