"""
Module: Subdomain Enumeration
Description: Discovers subdomains using a wordlist.
Author: CyberJBX
"""

import random
import string
import socket

def check_wildcard(domain):
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=10))
    test_domain = f"{random_sub}.{domain}"

    try:
        socket.gethostbyname(test_domain)
        return True  # wildcard detected
    except:
        return False
    


def run_subdomain_enum(target, mode="fast"):
    """Run subdomain enumeration using wordlist"""
    # ==========================
    # WILDCARD CHECK
    # ==========================
    found_subdomains = []
    if check_wildcard(target):
        print("[WARNING] Wildcard DNS detected - results may be inaccurate")
        print(f"[+] Running Subdomain Enumeration on {target}")

    # ==========================
    # NORMALIZE TARGET
    # ==========================
    if target.startswith("www."):
        target = target.replace("www.", "")

    # ==========================
    # LOAD WORDLIST BASED ON MODE
    # ==========================
    try:
        if mode == "fast":
            wordlist_file = "data/sub_small.txt"
        else:
            wordlist_file = "data/wordlist.txt"

        with open(wordlist_file, "r") as file:
            subdomains = file.read().splitlines()

    except FileNotFoundError:
        print("[-] Wordlist not found")
        return []

    # ==========================
    # BRUTE FORCE SUBDOMAINS
    # ==========================
    for sub in subdomains:

        # skip duplicate www
        if sub == "www":
            continue

        subdomain = f"{sub}.{target}"

        try:
            socket.gethostbyname(subdomain)

            if subdomain not in found_subdomains:
                print(f"[FOUND] {subdomain}")
                found_subdomains.append(subdomain)

        except socket.gaierror:
            pass
        
        if not found_subdomains:
            print("[INFO] No subdomains found")

    return found_subdomains