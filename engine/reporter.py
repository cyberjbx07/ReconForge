"""
Module: Reporting Engine
Description: Generates and saves scan reports to a file.
Author: CyberJBX
"""


def generate_report(target, analyzed_results):
    """Generate and save report"""

    file_path = "output/report.txt"

    with open(file_path, "w", encoding="utf-8") as f:

        # ==========================
        # HEADER
        # ==========================
        f.write(f"Target: {target}\n\n")

        f.write("[PORT ANALYSIS]\n\n")

        # ==========================
        # WRITE RESULTS
        # ==========================
        for item in analyzed_results:
            line = f"{item['port']} → {item['service']} → {item['risk']} RISK\n"
            f.write(line)

    print(f"\n[+] Report saved to {file_path}")