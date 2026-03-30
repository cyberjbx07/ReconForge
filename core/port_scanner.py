"""
Module: Port Scanner
Description: Scans target for open ports, services, and versions using Nmap.
Author: CyberJBX
"""

import nmap


def run_port_scan(target, mode="fast"):
    """Run port scan using Nmap"""

    scanner = nmap.PortScanner()
    results = []
    
    if mode == "fast":
        ports = "80,443,8080,8443"
        print(f"[+] Running Port Scan on {target}")
    else:
        ports = "1-65535"
        print(f"[+] Running Port Scan on {target}")

    # ==========================
    # NMAP SCAN EXECUTION
    # ==========================
    try:
        if mode == "fast":
            scanner.scan(hosts=target, arguments='-F')
        else:
            scanner.scan(hosts=target, arguments='-sS -sV')

    except Exception as e:
        print(f"[-] Scan error: {e}")
        return []

    # ==========================
    # PARSE SCAN RESULTS
    # ==========================
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()

            for port in ports:
                service = scanner[host][proto][port]['name']
                version = scanner[host][proto][port]['version']

                result = {
                    "port": port,
                    "service": service,
                    "version": version
                }

                results.append(result)

                print(f"[OPEN] {port} → {service} ({version})")
                
            if not results:
                print("[INFO] No open ports found")

    return results