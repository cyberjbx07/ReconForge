import dns.resolver

def run_dns_enum(target):
    print(f"[+] Running DNS Enumeration on {target}")

    dns_data = {
        "A": [],
        "MX": [],
        "NS": []
    }

    # ==========================
    # A RECORD
    # ==========================
    try:
        answers = dns.resolver.resolve(target, 'A')
        for r in answers:
            dns_data["A"].append(r.to_text())
    except Exception:
        print("[INFO] A record not found")

    # ==========================
    # MX RECORD
    # ==========================
    try:
        answers = dns.resolver.resolve(target, 'MX')
        for r in answers:
            dns_data["MX"].append(r.exchange.to_text())
    except Exception:
        print("[INFO] MX record not found")

    # ==========================
    # NS RECORD
    # ==========================
    try:
        answers = dns.resolver.resolve(target, 'NS')
        for r in answers:
            dns_data["NS"].append(r.to_text())
    except Exception:
        print("[INFO] NS record not found")

    # ==========================
    # PRINT RESULTS
    # ==========================
    print("\n[DNS RESULTS]")

    if not any(dns_data.values()):
        print("[INFO] No DNS data found")
    else:
        for record, values in dns_data.items():
            if values:
                print(f"{record}: {values}")
    
    return dns_data