import json
from constants import COMMON_PORTS
from utils import validate_host, is_valid_port_range

def get_user_input():
    while True:
        host = input("Enter the host (IP or Domain Name): ")
        if host == "q":
            return False
        if validate_host(host):
            break
        print("Invalid host. Try again or enter 'q' to quit.")

    while True:
        port_range = input("Enter the port range | Example: 0-1024): ")
        if port_range == "q":
            return False
        if is_valid_port_range(port_range):
            break
        print("Invalid port range. Try again or enter 'q' to quit.")

    return host, port_range

def print_scan_summary(open_ports, port_to_banner):
    print("Scan Summary:")
    print(f"{'Port':<8} {'Service':<15} {'Banner'}")
    print("-" * 60)
    for port in open_ports:
        service = COMMON_PORTS.get(port, "Unknown")
        banner = port_to_banner.get(port, "None")
        print(f"{port:<8} {service:<15} {banner}")

def export_json(summary_list):
    with open("scan_results.json", "w") as f:
        json.dump(summary_list, f, indent=4)
    print("Scan results exported to scan_results.json")
