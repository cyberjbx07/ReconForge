"""
Module: Subdomain Enumeration
Description: Discovers subdomains using a wordlist.
Author: CyberJBX
"""

import random
import string
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from utils.colors import open_port, info, warning
from colorama import Fore


def check_wildcard(domain):
    """Check if wildcard DNS is enabled"""
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=10))
    test_domain = f"{random_sub}.{domain}"

    try:
        socket.gethostbyname(test_domain)
        return True  # wildcard detected
    except:
        return False


def check_subdomain(target, sub):
    """
    Resolve a single subdomain

    Returns:
        str | None
    """
    if sub == "www":
        return None

    subdomain = f"{sub}.{target}"

    try:
        socket.gethostbyname(subdomain)
        return subdomain
    except socket.gaierror:
        return None


def run_subdomain_enum(target, mode="fast"):
    """Run subdomain enumeration using wordlist"""

    found_subdomains = []

    # ==========================
    # WILDCARD CHECK
    # ==========================
    if check_wildcard(target):
        warning("[WARNING] Wildcard DNS detected - results may be inaccurate")

    info(f"[+] Running Subdomain Enumeration on {target}\n")

    # ==========================
    # NORMALIZE TARGET
    # ==========================
    if target.startswith("www."):
        target = target.replace("www.", "")

    # ==========================
    # LOAD WORDLIST
    # ==========================
    try:
        if mode == "fast":
            wordlist_file = "data/sub_small_wordlist.txt"
        else:
            wordlist_file = "data/wordlist.txt"

        with open(wordlist_file, "r") as file:
            subdomains = file.read().splitlines()

    except FileNotFoundError:
        warning("[-] Wordlist not found")
        return []

    # ==========================
    # THREAD + PROGRESS BAR
    # ==========================
    with ThreadPoolExecutor(max_workers=20) as executor:

        # create tasks
        futures = [executor.submit(check_subdomain, target, sub) for sub in subdomains]

        # progress bar with clean output
        for future in tqdm(as_completed(futures), total=len(futures), desc="Subdomain Scan"):
            result = future.result()

            if result and result not in found_subdomains:
                found_subdomains.append(result)

                # ✅ IMPORTANT: clean print
                tqdm.write(Fore.GREEN + f"[FOUND] {result}")

    # ==========================
    # FINAL RESULT
    # ==========================
    if not found_subdomains:
        warning("\n[INFO] No subdomains found")

    return found_subdomains