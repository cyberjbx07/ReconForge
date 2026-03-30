from core.input import get_target
from core.dns_enum import run_dns_enum
from core.subdomain_enum import run_subdomain_enum
from core.port_scanner import run_port_scan
from engine.analyzer import analyze_ports
from engine.reporter import generate_report
from core.dir_enum import run_dir_enum
import argparse



# ==========================
# UI HELPERS
# ==========================
def banner():
    print("""
    =============================
        ReconForge v2.5
        Author: CyberJBX
    =============================
    """)

def print_section(title):
    print(f"\n{'='*10} {title} {'='*10}")

def get_args():
    parser = argparse.ArgumentParser(description="ReconForge Tool")
    parser.add_argument("-t", "--target", help="Target domain or IP")
    return parser.parse_args()


# ==========================
# MENU SYSTEM
# ==========================
def show_menu():
    print("\n========== ReconForge Menu ==========")
    print("1. Fast All Recon Scan")
    print("2. Full All Recon Scan")
    print("3. DNS Enumeration")
    print("4. Subdomain Enumeration")
    print("5. Port Scan (Fast)")
    print("6. Port Scan (Full)")
    print("7. Directory Enumeration")
    print("8. Technology Detection")
    print("9. Security Header Analysis")
    print("0. Exit")

    return input("Select an option: ")

def main():
    banner()

    args = get_args()

    # ==========================
    # GET TARGET (ONLY ONCE)
    # ==========================
    if args.target:
        target = args.target
    else:
        target = get_target()

    # ==========================
    # MENU LOOP
    # ==========================
    while True:
        choice = show_menu()

        if choice == "0":
            print("[INFO] Exiting...")
            break
        
        if choice == "1":
            print("[DEBUG] Entered Fast All Recon Scan")  # 👈 add this
            run_port_scan(target, "full")
            print("[DEBUG] DNS START")
            run_dns_enum(target)

            print("[DEBUG] SUBDOMAIN START")
            run_subdomain_enum(target, "fast")

            print("[DEBUG] PORT SCAN START")
            run_port_scan(target, "fast")

            print("[DEBUG] DIR ENUM START")
            run_dir_enum(target, "fast")
    # ==========================
    # MENU HANDLER
    # ==========================

    if choice == "1":
        print("[INFO] Running Fast All Recon Scan")

        run_dns_enum(target)
        run_subdomain_enum(target, "fast")
        run_port_scan(target, "fast")
        run_dir_enum(target, "fast")

    elif choice == "2":
        print("[INFO] Running Full All Recon Scan")

        run_dns_enum(target)
        subs = run_subdomain_enum(target)
        run_port_scan(target)   # full version (later optimize)
        run_dir_enum(target)

    elif choice == "3":
        run_dns_enum(target)

    elif choice == "4":
        run_subdomain_enum(target)

    elif choice == "5":
        run_port_scan(target)

    elif choice == "6":
        run_port_scan(target)  # later full mode add karenge

    elif choice == "7":
        run_dir_enum(target)

    elif choice == "8":
        print("[INFO] Tech Detection runs with directory scan")
        run_dir_enum(target)

    elif choice == "9":
        print("[INFO] Header analysis runs with directory scan")
        run_dir_enum(target)

    elif choice == "0":
        exit()

    else:
        print("[ERROR] Invalid option")
    
    if not target:
        return

    # ==========================
    # DNS ENUMERATION
    # ==========================
    dns_data = run_dns_enum(target)

    print_section("DNS RESULTS")
    for record, values in dns_data.items():
        print(f"{record}: {values}")

    # ==========================
    # SUBDOMAIN ENUMERATION
    # ==========================
    subdomains = run_subdomain_enum(target)

    print("\n[SUBDOMAINS FOUND]")
    for sub in subdomains:
        print(sub)

    # ==========================
    # PORT SCANNING (COLLECT ALL)
    # ==========================
    unique_targets = list(set([target] + subdomains))
    all_results = []   # ✅ important

    print("\n[PORT SCAN RESULTS]")

    for t in unique_targets:
        print(f"\n[SCANNING] {t}")

        scan_results = run_port_scan(t)
        analyzed_results = analyze_ports(scan_results)

        for item in analyzed_results:
            item["target"] = t   # ✅ add target info
            all_results.append(item)

            print(f"{item['port']} → {item['service']} → {item['risk']} RISK")
            
    # ==========================
    # DIRECTORY ENUMERATION
    # ==========================
    dir_results = run_dir_enum(target)

    print("\n[DIRECTORIES FOUND]")

    # ==========================
    # TECH DETECTION ABD MISSING HEADERS
    # ==========================
    if dir_results:
        for d in dir_results:
            print(f"{d['path']} → {d['status']} | size: {d['size']} | server: {d['server']}")
            
            if d["tech"]:
                print("  Tech Detected:")
                for t in d["tech"]:
                    print(f"   - {t}")

            if d["missing_headers"]:
                print("  Missing Headers:")
                for h in d["missing_headers"]:
                    print(f"   - {h}")
    else:
        print("No directories found")
        
    # ==========================
    # GENERATE FINAL REPORT (ONCE)
    # ==========================
    generate_report(target, dns_data, subdomains, all_results, dir_results)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")
        exit(0)