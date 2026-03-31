# ==========================
# IMPORTS
# ==========================
import argparse
import re
import socket

from core.input import get_target
from core.dns_enum import run_dns_enum
from core.subdomain_enum import run_subdomain_enum
from core.port_scanner import run_port_scan
from core.dir_enum import run_dir_enum
from engine.reporter import generate_report


# ==========================
# GLOBAL SCAN STORAGE
# ==========================
scan_data = {
    "dns": {},
    "subdomains": [],
    "ports": [],
    "dirs": []
}


# ==========================
# SAVE PROMPT FUNCTION
# ==========================
def ask_to_save(target, scan_data):
    """
    Ask user to save report (default: YES)
    """

    print("\n" + "="*40)
    choice = input("Save report? (Y/n): ").strip().lower()
    print("="*40)

    if choice in ["", "y", "yes"]:
        generate_report(
            target,
            scan_data.get("dns", {}),
            scan_data.get("subdomains", []),
            scan_data.get("ports", []),
            scan_data.get("dirs", [])
        )
    else:
        print("[INFO] Report not saved")


# ==========================
# HELPER FUNCTIONS
# ==========================
def section(title):
    print(f"\n[INFO]========== {title} ==========\n")


def is_ip(target):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)


def handle_ip_target(target):
    print("[WARNING] Target is an IP. Skipping DNS & Subdomain")

    try:
        domain = socket.gethostbyaddr(target)
        print(f"[INFO] Reverse DNS: {domain[0]}")
    except:
        print("[INFO] No reverse DNS found")


# ==========================
# UI
# ==========================
def banner():
    print("""
    =============================
        ReconForge v2.5
        Author: CyberJBX
    =============================
    """)


def get_args():
    parser = argparse.ArgumentParser(description="ReconForge Tool")
    parser.add_argument("-t", "--target", help="Target domain or IP")
    return parser.parse_args()


# ==========================
# MENU
# ==========================
def show_menu():
    print("\n[+]========== ReconForge Menu ==========[+]")
    print("[1] Fast All Recon Scan")
    print("[2] Full All Recon Scan")
    print("[3] DNS Enumeration")
    print("[4] Subdomain Enumeration")
    print("[5] Port Scan (Fast)")
    print("[6] Port Scan (Full)")
    print("[7] Directory Enumeration (INCLUDES TECH & HEADERS)")
    print("[8] Change Target")
    print("[0] Exit")

    return input("\nSelect an option: ")


# ==========================
# MAIN FUNCTION
# ==========================
def main():
    banner()

    args = get_args()

    # ==========================
    # TARGET INPUT (ONLY ONCE)
    # ==========================
    if args.target:
        target = args.target
    else:
        target = get_target()

    # ==========================
    # MENU LOOP
    # ==========================
    while True:
        print(f"\n[INFO] Current Target: {target}")

        choice = show_menu()

        is_target_ip_flag = is_ip(target)

        # Reset scan_data for every run
        global scan_data
        scan_data = {
            "dns": {},
            "subdomains": [],
            "ports": [],
            "dirs": []
        }

        # ==========================
        # OPTION 1: FAST RECON
        # ==========================
        if choice == "1":
            section("FAST ALL RECON SCAN")

            if is_target_ip_flag:
                handle_ip_target(target)

                section("PORT SCAN")
                scan_data["ports"] = run_port_scan(target, "fast")

                section("DIRECTORY ENUMERATION")
                scan_data["dirs"] = run_dir_enum(target, "fast")

            else:
                section("DNS ENUMERATION")
                scan_data["dns"] = run_dns_enum(target)

                print("\n" + "-"*50)

                section("SUBDOMAIN ENUMERATION")
                scan_data["subdomains"] = run_subdomain_enum(target, "fast")

                print("\n" + "-"*50)

                section("PORT SCAN")
                scan_data["ports"] = run_port_scan(target, "fast")

                print("\n" + "-"*50)

                section("DIRECTORY ENUMERATION")
                scan_data["dirs"] = run_dir_enum(target, "fast")

            ask_to_save(target, scan_data)

        # ==========================
        # OPTION 2: FULL RECON
        # ==========================
        elif choice == "2":
            section("FULL ALL RECON SCAN")

            if is_target_ip_flag:
                handle_ip_target(target)
                scan_data["ports"] = run_port_scan(target, "full")
                scan_data["dirs"] = run_dir_enum(target, "full")

            else:
                scan_data["dns"] = run_dns_enum(target)
                scan_data["subdomains"] = run_subdomain_enum(target, "full")
                scan_data["ports"] = run_port_scan(target, "full")
                scan_data["dirs"] = run_dir_enum(target, "full")

            ask_to_save(target, scan_data)

        # ==========================
        # OPTION 3: DNS
        # ==========================
        elif choice == "3":
            section("DNS ENUMERATION")

            if is_target_ip_flag:
                print("[INFO] Skipped (IP detected)")
            else:
                scan_data["dns"] = run_dns_enum(target)

            ask_to_save(target, scan_data)

        # ==========================
        # OPTION 4: SUBDOMAIN
        # ==========================
        elif choice == "4":
            section("SUBDOMAIN ENUMERATION")

            if is_target_ip_flag:
                print("[INFO] Skipped (IP detected)")
            else:
                scan_data["subdomains"] = run_subdomain_enum(target, "fast")

            ask_to_save(target, scan_data)

        # ==========================
        # OPTION 5: PORT FAST
        # ==========================
        elif choice == "5":
            section("FAST PORT SCAN")
            scan_data["ports"] = run_port_scan(target, "fast")
            ask_to_save(target, scan_data)

        # ==========================
        # OPTION 6: PORT FULL
        # ==========================
        elif choice == "6":
            section("FULL PORT SCAN")
            scan_data["ports"] = run_port_scan(target, "full")
            ask_to_save(target, scan_data)

        # ==========================
        # OPTION 7: DIRECTORY
        # ==========================
        elif choice == "7":
            section("DIRECTORY ENUMERATION")
            scan_data["dirs"] = run_dir_enum(target, "full")
            ask_to_save(target, scan_data)

        # ==========================
        # OPTION 8: CHANGE TARGET
        # ==========================
        elif choice == "8":
            section("CHANGE TARGET")
            target = get_target().strip().lower()
            print(f"[INFO] Target updated to: {target}")
            continue

        # ==========================
        # EXIT
        # ==========================
        elif choice == "0":
            print("[INFO] Exiting...\n")
            break

        else:
            print("[ERROR] Invalid option")


# ==========================
# ENTRY POINT
# ==========================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")