"""
Module: Reporting Engine
Description: Generates complete scan report in structured TXT format.
Author: CyberJBX
"""

import os
from datetime import datetime


def generate_report(target, dns_data, subdomains, analyzed_results, dir_results):
    """
    Generate a full reconnaissance report and save it to a TXT file.

    Args:
        target (str): Target domain/IP
        dns_data (dict): DNS records (A, MX, NS)
        subdomains (list): Discovered subdomains
        analyzed_results (list): Port scan results with risk analysis
        dir_results (list): Directory enumeration results
    """

    # ==========================
    # ENSURE OUTPUT DIRECTORY EXISTS
    # ==========================
    os.makedirs("output", exist_ok=True)

    # ==========================
    # CLEAN TARGET FOR FILE NAME
    # ==========================
    # Clean target
    safe_target = target.replace("https://", "").replace("http://", "")
    safe_target = safe_target.replace("/", "").replace(".", "_")

    # Add timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    folder = f"output/{safe_target}"
    os.makedirs(folder, exist_ok=True)

    file_path = f"{folder}/{safe_target}_{timestamp}.txt"

    # ==========================
    # OPEN FILE FOR WRITING
    # ==========================
    with open(file_path, "w", encoding="utf-8") as f:

        # ==========================
        # REPORT HEADER
        # ==========================
        f.write("=" * 50 + "\n")
        f.write("        ReconForge Scan Report\n")
        f.write("=" * 50 + "\n\n")

        f.write(f"Target: {target}\n\n")

        # ==========================
        # DNS DATA
        # ==========================
        f.write("[DNS DATA]\n")

        if dns_data:
            for record, values in (dns_data or {}).items():
                f.write(f"{record}: {values}\n")
        else:
            f.write("No DNS data found\n")

        f.write("\n" + "-" * 50 + "\n\n")

        # ==========================
        # SUBDOMAINS
        # ==========================
        f.write("[SUBDOMAINS]\n")

        if subdomains:
            for sub in subdomains:
                f.write(f"{sub}\n")
        else:
            f.write("No subdomains found\n")

        f.write("\n" + "-" * 50 + "\n\n")

        # ==========================
        # PORT ANALYSIS
        # ==========================
        f.write("[PORT ANALYSIS]\n\n")

        if analyzed_results:
            for item in analyzed_results:
                target_name = item.get("target", target)

                line = (
                    f"{target_name} → {item.get('port', 'N/A')} → "
                    f"{item.get('service', 'unknown')} → {item.get('risk', 'unknown')} RISK\n"
                )
        else:
            f.write("No open ports found\n")

        f.write("\n" + "-" * 50 + "\n\n")

        # ==========================
        # DIRECTORY ENUMERATION
        # ==========================
        f.write("[DIRECTORIES]\n\n")

        if dir_results:
            for d in dir_results:
                # Basic directory info
                line = (
                    f"{d.get('path', 'N/A')} → {d.get('status', 'N/A')} | "
                    f"size: {d.get('size', 'N/A')} | server: {d.get('server', 'Unknown')}\n"
                )
                f.write(line)

                # --------------------------
                # Missing Security Headers
                # --------------------------
                if d.get("missing_headers"):
                    f.write("  Missing Headers:\n")
                    for h in d["missing_headers"]:
                        f.write(f"   - {h}\n")
                else:
                    f.write("  Missing Headers: None\n")

                # --------------------------
                # Technology Detection
                # --------------------------
                if d.get("tech"):
                    f.write("  Tech Detected:\n")
                    for t in d["tech"]:
                        f.write(f"   - {t}\n")
                else:
                    f.write("  Tech Detected: None\n")

                # Separator between directories
                f.write("-" * 40 + "\n")

        else:
            f.write("No directories found\n")

        f.write("\n" + "=" * 50 + "\n")

    # ==========================
    # SUCCESS MESSAGE
    # ==========================
    print(f"\n[INFO] Report saved to: {file_path}")