"""
Module: Analysis Engine
Description: Analyzes scan results and assigns risk levels.
Author: CyberJBX
"""


def analyze_ports(scan_results):
    """Analyze port scan results and assign risk levels"""

    analyzed_data = []

    for item in scan_results:
        port = item["port"]
        service = item["service"]

        # ==========================
        # RISK CLASSIFICATION LOGIC
        # ==========================
        if port in [21, 23, 445]:
            risk = "HIGH"
        elif port in [22, 80]:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        analyzed_data.append({
            "port": port,
            "service": service,
            "risk": risk
        })

    return analyzed_data