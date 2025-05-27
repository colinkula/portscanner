import ipaddress
import socket
import re
import time
import json

# Mapping of common ports to service descriptions
COMMON_PORTS = {
    20: "FTP Data Transfer", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP (Email Sending)",
    53: "DNS", 67: "DHCP (Server)", 68: "DHCP (Client)", 69: "TFTP", 80: "HTTP (Web)",
    110: "POP3 (Email Receiving)", 119: "NNTP (Usenet)", 123: "NTP (Time Sync)", 135: "RPC",
    137: "NetBIOS Name Service", 138: "NetBIOS Datagram", 139: "NetBIOS Session", 143: "IMAP (Email Receiving)",
    161: "SNMP", 162: "SNMP Trap", 179: "BGP", 389: "LDAP", 443: "HTTPS (Secure Web)",
    445: "Microsoft-DS (SMB file sharing)", 465: "SMTPS", 514: "Syslog", 587: "SMTP (with TLS)",
    631: "IPP (Printing)", 993: "IMAPS (Secure IMAP)", 995: "POP3S (Secure POP3)", 1433: "MSSQL",
    1521: "Oracle DB", 1723: "PPTP VPN", 2049: "NFS", 2082: "cPanel", 2083: "cPanel (Secure)",
    2483: "Oracle DB Listener", 2484: "Oracle DB Listener (Secure)", 3306: "MySQL",
    3389: "RDP (Remote Desktop)", 3690: "Subversion", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)", 6379: "Redis", 6667: "IRC",
    8000: "HTTP Alt", 8080: "HTTP Proxy/Alt", 8443: "HTTPS Alt", 8888: "Web Servers (Dev)",
    9001: "Tor ORPort", 9200: "Elasticsearch", 10000: "Webmin"
}


# ------------------- Input Validation -------------------

def get_user_input():
    while True:
        host = input("Enter the host (IP or Domain Name): ")
        if host.lower() == "q":
            return None, None
        if validate_host(host):
            break
        print("Invalid host. Try again or enter 'q' to quit.")

    while True:
        port_range = input("Enter the port range | Example: 0-1024: ")
        if port_range.lower() == "q":
            return None, None
        if is_valid_port_range(port_range):
            break
        print("Invalid port range. Try again or enter 'q' to quit.")

    return host, port_range


def validate_host(host):
    return is_valid_ip(host) or is_valid_domain_name(host)


def is_valid_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_valid_domain_name(host):
    domain_regex = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    return re.match(domain_regex, host) is not None


def is_valid_port_range(port_range):
    if "-" not in port_range:
        return False
    try:
        start, end = map(int, port_range.split("-"))
        return 0 <= start <= end <= 65535
    except ValueError:
        return False


# ------------------- Scanning Logic -------------------

def scan(host, port_range):
    print(f"Scan initiated for {host} in range {port_range}")
    start_port, end_port = map(int, port_range.split("-"))
    ports_to_scan = [p for p in COMMON_PORTS if start_port <= p <= end_port]

    if not ports_to_scan:
        print("No common ports fall within this range.")
        return 0, [], {}, {}

    open_ports = []
    port_to_banner = {}
    port_to_time = {}

    start_total = time.time()

    for port in ports_to_scan:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                start_time = time.time()
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
                    try:
                        banner = sock.recv(1024).decode(errors="ignore").strip()
                        port_to_banner[port] = banner if banner else "Uncertain"
                    except:
                        port_to_banner[port] = "Uncertain"
                    port_to_time[port] = time.time() - start_time
        except Exception:
            continue

    total_time = time.time() - start_total

    print_scan_summary(open_ports, port_to_banner)
    print(f"\nScan completed in {total_time:.2f} seconds.")
    return total_time, open_ports, port_to_banner, port_to_time


# ------------------- Output -------------------

def print_scan_summary(open_ports, port_to_banner):
    print("\nScan Summary:")
    print(f"{'Port':<8} {'Service':<15} {'Banner'}")
    print("-" * 60)
    for port in open_ports:
        service = COMMON_PORTS.get(port, "Unknown")
        banner = port_to_banner.get(port, "None")
        print(f"{port:<8} {service:<15} {banner}")


def create_export_dict(host, port_range, open_ports, port_to_banner, port_to_time, total_time):
    return {
        "host": host,
        "scanned_port_range": port_range,
        "total_execution_time": round(total_time, 2),
        "open_ports": {
            port: {
                "service": COMMON_PORTS.get(port, "Unknown"),
                "banner": port_to_banner.get(port, "Uncertain"),
                "status": "OPEN",
                "execution_time": round(port_to_time.get(port, 0), 2)
            }
            for port in open_ports
        }
    }


def export_json(summary_list):
    with open("scan_results.json", "w") as file:
        json.dump(summary_list, file, indent=4)
    print("Scan results exported to scan_results.json")


# ------------------- Main Application -------------------

def main():
    print("Welcome to the multi-host port scanner!")
    host_to_port_range = {}

    host, port_range = get_user_input()
    if host and port_range:
        host_to_port_range[host] = port_range

    while True:
        choice = input("Would you like to scan another host? (y/n): ").strip().lower()
        if choice == "n":
            break
        elif choice == "y":
            host, port_range = get_user_input()
            if host and port_range:
                host_to_port_range[host] = port_range
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

    summary_list = []
    for host, port_range in host_to_port_range.items():
        print(f"\n--- Scanning {host} ---")
        scan_time, open_ports, banners, times = scan(host, port_range)
        summary = create_export_dict(host, port_range, open_ports, banners, times, scan_time)
        summary_list.append(summary)

    export_json(summary_list)


if __name__ == "__main__":
    main()
