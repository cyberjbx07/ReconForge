"""
Module: Directory Enumeration
Description: Finds hidden directories + analyzes responses
Author: CyberJBX
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from utils.colors import open_port, info, warning
from colorama import Fore




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

    info(f"[+] Running Directory Enumeration on {target}\n")

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
        warning("[-] Wordlist not found")
        return []

    # ==========================
    # ENUMERATION LOGIC
    # ==========================
    found_dirs = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_directory, target, d) for d in dirs]

        for future in tqdm(as_completed(futures), total=len(futures), desc="Directory Scan"):
            result = future.result()

            if result:
                found_dirs.append(result)

                # ==========================
                # MAIN RESULT (GREEN)
                # ==========================
                tqdm.write(
                    Fore.GREEN +
                    f"[FOUND] {result['path']} → {result['status']} | size: {result['size']} | server: {result['server']}"
                )

                # ==========================
                # TECH DETECTION (CYAN HEADER)
                # ==========================
                if result["tech"]:
                    tqdm.write(Fore.CYAN + "  Tech Detected:")
                    for t in result["tech"]:
                        tqdm.write(Fore.CYAN + f"   - {t}")
                else:
                    tqdm.write(Fore.CYAN + "  Tech Detected: None")

                # ==========================
                # MISSING HEADERS (RED)
                # ==========================
                if result["missing_headers"]:
                    tqdm.write(Fore.RED + "  Missing Headers:")
                    for h in result["missing_headers"]:
                        tqdm.write(Fore.RED + f"   - {h}")
                else:
                    tqdm.write(Fore.YELLOW + "  Missing Headers: None")

                # ==========================
                # SEPARATOR
                # ==========================
                tqdm.write(Fore.MAGENTA + "-" * 40)
        

        # ==========================
        # AFTER LOOP ONLY
        # ==========================
        if not found_dirs:
            warning("\n[INFO] No directories found")

    return found_dirs