import json

def get_banner(sock):
    try:
        return sock.recv(1024).decode(errors="ignore").strip() or "Uncertain"
    except:
        return "Uncertain"

def print_summary(host, open_ports, port_data, total_time):
    print(f"\nScan results for {host}")
    print(f"{'Port':<8} {'Service':<15} {'Banner'}")
    print("-" * 60)
    for port in open_ports:
        data = port_data[port]
        print(f"{port:<8} {data['service']:<15} {data['banner']}")
    print(f"\nScan completed in {total_time:.2f} seconds.")

def export_json(data):
    with open("scan_results.json", "w") as f:
        json.dump(data, f, indent=4)
    print("Results exported to scan_results.json")
