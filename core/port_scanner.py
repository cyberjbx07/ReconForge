"""
Module: Port Scanner
Description: Scans target for open ports, services, and versions using Nmap.
Author: CyberJBX
"""

import nmap
from utils.colors import open_port, info, warning


def run_port_scan(target, mode="fast"):
    """Run port scan using Nmap"""

    # ==========================
    # INITIALIZE SCANNER
    # ==========================
    scanner = nmap.PortScanner()
    results = []

    info(f"[+] Running Port Scan on {target}\n")

    # ==========================
    # OPTIONAL PROGRESS 
    # ==========================

    open_port("Scanning ports... please wait")
    
    # ==========================
    # NMAP SCAN EXECUTION
    # ==========================
    try:
        if mode == "fast":
            # Fast scan → top ports only
            scanner.scan(hosts=target, arguments='-F')

        else:
            # Full scan → optimized (not full 65535, but realistic)
            scanner.scan(hosts=target, arguments='-T4 -sS -sV --top-ports 1000')

    except Exception as e:
        warning(f"[-] Scan error: {e}")
        return []

    # ==========================
    # PARSE SCAN RESULTS
    # ==========================
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():

            ports = scanner[host][proto].keys()

            for port in ports:

                # Safe extraction (avoid KeyError)
                service = scanner[host][proto][port].get('name', 'unknown')
                version = scanner[host][proto][port].get('version', '')

                # ==========================
                # BUILD RESULT OBJECT
                # ==========================
                risk = ""
                if port in [21, 23, 25, 110, 143]:
                    risk = "HIGH"
                elif port in [80, 443]:
                    risk = "MEDIUM"
                else:
                    risk = "LOW"
                result = {
                    "target": target,
                    "port": port,
                    "service": service,
                    "version": version,
                    "risk": risk 
                }

                results.append(result)

                # ==========================
                # PRINT OUTPUT
                # ==========================
                open_port(f"[OPEN] {port} → {service} ({version}) → {result['risk']}")

    # ==========================
    # NO RESULT CASE
    # ==========================
    if not results:
        warning("[INFO] No open ports found")

    return results