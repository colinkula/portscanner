import json
import re
from constants import MAX_BANNER_LENGTH

def get_banner(sock):
    try:
        return sock.recv(1024).decode(errors="ignore").strip() or "Uncertain"
    except:
        return "Uncertain"

def sanitize_banner(raw_banner, max_length: int = MAX_BANNER_LENGTH):
    if not raw_banner:
        return ""

    banner = re.sub(r'\s+', ' ', raw_banner.strip())
    banner = ''.join(c if c.isprintable() else '.' for c in banner)

    if len(banner) > max_length:
        banner = banner[:max_length - 3] + '...'

    return banner

def print_summary(host, open_ports, port_data, total_time):
    print(f"\nScan results for {host}")
    print(f"{'Port':<8} {'Service':<15} {'Banner'}")
    print("-" * 60)

    for port in sorted(open_ports):
        service = port_data.get(port, {}).get('service', 'unknown')
        raw_banner = port_data.get(port, {}).get('banner', '')
        banner = sanitize_banner(raw_banner)
        print(f"{port:<8} {service:<15} {banner}")

    print(f"\nScan completed in {total_time:.2f} seconds.")

def export_json(data):
    with open("scan_results.json", "w") as f:
        json.dump(data, f, indent=4)
    print("Results exported to scan_results.json")
