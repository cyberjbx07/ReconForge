"""
Module: DNS Enumeration
Description: Retrieves A, MX, and NS records for a given target.
Author: CyberJBX
"""

import dns.resolver


def run_dns_enum(target):
    """Run DNS enumeration on target"""

    results = {}

    print(f"[+] Running DNS Enumeration on {target}")

    # ==========================
    # DNS RECORD: A (IP Address)
    # ==========================
    try:
        answers = dns.resolver.resolve(target, 'A')
        results['A'] = [str(rdata) for rdata in answers]
    except Exception:
        results['A'] = []

    # ==========================
    # DNS RECORD: MX (Mail Server)
    # ==========================
    try:
        answers = dns.resolver.resolve(target, 'MX')
        results['MX'] = [str(rdata.exchange) for rdata in answers]
    except Exception:
        results['MX'] = []

    # ==========================
    # DNS RECORD: NS (Name Server)
    # ==========================
    try:
        answers = dns.resolver.resolve(target, 'NS')
        results['NS'] = [str(rdata) for rdata in answers]
    except Exception:
        results['NS'] = []
        
    if not any(results.values()):
        print("[INFO] No DNS records found")

    return results