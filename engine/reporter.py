"""
Module: Reporting Engine
Description: Generates complete scan report.
Author: CyberJBX
"""

import os


def generate_report(target, dns_data, subdomains, analyzed_results, dir_results):
    """Generate full report in single file"""

    safe_target = target.replace(".", "_")
    file_path = f"output/{safe_target}.txt"

    with open(file_path, "w", encoding="utf-8") as f:

        # ==========================
        # HEADER
        # ==========================
        f.write(f"Target: {target}\n\n")

        # ==========================
        # DNS DATA
        # ==========================
        f.write("[DNS DATA]\n")

        for record, values in dns_data.items():
            f.write(f"{record}: {values}\n")

        f.write("\n")

        # ==========================
        # SUBDOMAINS
        # ==========================
        f.write("[SUBDOMAINS]\n")

        for sub in subdomains:
            f.write(f"{sub}\n")

        f.write("\n")

        # ==========================
        # PORT ANALYSIS
        # ==========================
        f.write("[PORT ANALYSIS]\n\n")

        for item in analyzed_results:
            line = f"{item['target']} → {item['port']} → {item['service']} → {item['risk']} RISK\n"
            f.write(line)
            
        # ==========================
        # DIRECTORIES
        # ==========================
        f.write("[DIRECTORIES]\n")

        if dir_results:
            for d in dir_results:
                line = f"{d['path']} → {d['status']} | size: {d['size']} | server: {d['server']}\n"
                f.write(line)
                
                # ==========================
                # WRITE MISSING HEADERS
                # ==========================
                if d["missing_headers"]:
                    f.write("  Missing Headers:\n")
                    for h in d["missing_headers"]:
                        f.write(f"   - {h}\n")

        else:
            f.write("No directories found\n")

        f.write("\n")

    print(f"\n[+] Report saved to {file_path}")