from core.input import get_target
from core.dns_enum import run_dns_enum
from core.subdomain_enum import run_subdomain_enum
from core.port_scanner import run_port_scan
from engine.analyzer import analyze_ports
from engine.reporter import generate_report
from core.dir_enum import run_dir_enum


def main():
    target = get_target()
    
    if not target:
        return

    # ==========================
    # DNS ENUMERATION
    # ==========================
    dns_data = run_dns_enum(target)

    print("\n[DNS RESULTS]")
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
    all_targets = [target] + subdomains
    all_results = []   # ✅ important

    print("\n[PORT SCAN RESULTS]")

    for t in all_targets:
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

    if dir_results:
        for d in dir_results:
            print(f"{d['path']} → {d['status']} | size: {d['size']} | server: {d['server']}")

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
    main()