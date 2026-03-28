"""
Module: Port Scanner
Description: Scans target for open ports, services, and versions using Nmap.
Author: CyberJBX
"""

import nmap


def run_port_scan(target):
    """Run port scan using Nmap"""

    scanner = nmap.PortScanner()
    results = []

    print(f"[+] Running Port Scan on {target}")

    # ==========================
    # NMAP SCAN EXECUTION
    # ==========================
    try:
        scanner.scan(hosts=target, arguments='-F') # for fast scan
        # scanner.scan(hosts=target, arguments='-sS -sV') #for full scan
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

    return results