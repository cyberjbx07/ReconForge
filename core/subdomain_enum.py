"""
Module: Subdomain Enumeration
Description: Discovers subdomains using a wordlist.
Author: CyberJBX
"""

import socket


def run_subdomain_enum(target):
    """Run subdomain enumeration using wordlist"""

    found_subdomains = []

    print(f"[+] Running Subdomain Enumeration on {target}")

    # ==========================
    # LOAD WORDLIST
    # ==========================
    try:
        with open("data/wordlist.txt", "r") as file:
            subdomains = file.read().splitlines()
    except FileNotFoundError:
        print("[-] Wordlist not found")
        return []

    # ==========================
    # BRUTE FORCE SUBDOMAINS
    # ==========================
    for sub in subdomains:
        subdomain = f"{sub}.{target}"

        try:
            socket.gethostbyname(subdomain)
            print(f"[FOUND] {subdomain}")
            found_subdomains.append(subdomain)
        except socket.gaierror:
            pass  # Ignore invalid subdomains

    return found_subdomains