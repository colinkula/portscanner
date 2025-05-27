import ipaddress
import socket
import re
import time
import json

COMMON_PORTS = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Email Sending)",
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP",
    80: "HTTP (Web)",
    110: "POP3 (Email Receiving)",
    119: "NNTP (Usenet)",
    123: "NTP (Time Sync)",
    135: "RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP (Email Receiving)",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS (Secure Web)",
    445: "Microsoft-DS (SMB file sharing)",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP (with TLS)",
    631: "IPP (Printing)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP VPN",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel (Secure)",
    2483: "Oracle DB Listener",
    2484: "Oracle DB Listener (Secure)",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    3690: "Subversion",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    6379: "Redis",
    6667: "IRC",
    8000: "HTTP Alt",
    8080: "HTTP Proxy/Alt",
    8443: "HTTPS Alt",
    8888: "Web Servers (Dev)",
    9001: "Tor ORPort",
    9200: "Elasticsearch",
    10000: "Webmin",
}

def get_user_input():
    host = ""
    port_range = ""

    while True:
        host = input("Enter the host (IP or Domain Name): ")

        if host == "q":
            return False
        
        if validate_host(host):
            break
        print("Invalid host. Try again or enter 'q' to quit.")

    # Loop until user chooses correct syntax for port number range
    while True:
        # Get input and store it
        port_range = input("Enter the port range | Example: 0-1024): ")
        # Quit if user desires
        if port_range == "q":
            return False
        # Validate port range by calling is_valid_port_range function
        if is_valid_port_range(port_range):
            break
        print("Invalid port range. Try again or enter 'q' to quit.")

    return host, port_range

def validate_host(host):
    if is_valid_ip(host):
        return True
    elif is_valid_domain_name(host):
        return True
    else:
        return False

def is_valid_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
    
def is_valid_domain_name(host):
    domain_regex = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    if re.match(domain_regex, host):
        return True
    return False

def is_valid_port_range(port_range):
    # If the hyphen is not in the user input for the port_range, then automatically return false
    if "-" not in port_range:
        return False
    
    try:
        start_str, end_str = port_range.split("-")
        start_num = int(start_str)
        end_num = int(end_str)
        if 0 <= start_num <= 65535 and 1 <= end_num <= 65535 and start_num <= end_num:
            return True
    except ValueError:
        return False

    return False

def create_export_dict(host, port_range, open_ports, port_to_banner, port_to_time, total_time):
    export_dict = {
        "host": host,
        "scanned_port_range": port_range,
        "total_execution_time": round(total_time, 2),
        "open_ports": {}
    }

    for port in open_ports:
        export_dict["open_ports"][port] = {
            "service": COMMON_PORTS.get(port, "Unknown"),
            "banner": port_to_banner.get(port, "Uncertain"),
            "status": "OPEN",
            "execution_time": round(port_to_time.get(port, 0), 2)
        }

    return export_dict

def export_json(summary_list):
    with open("scan_results.json", "w") as file:
        json.dump(summary_list, file, indent=4)
    print("Scan results exported to scan_results.json")

def print_scan_summary(open_ports, port_to_banner):
    print("Scan Summary:")
    print(f"{'Port':<8} {'Service':<15} {'Banner'}")
    print("-" * 60)

    for port in open_ports:
        service = COMMON_PORTS.get(port, "Unknown")
        banner = port_to_banner.get(port, "None")
        print(f"{port:<8} {service:<15} {banner}")

def scan(host, port_range):
    print(f"Scan initiated for {host} in range {port_range}")
    
    start_port, end_port = map(int, port_range.split("-"))
    
    scan_ports = [port for port in COMMON_PORTS if start_port <= port <= end_port]
    if not scan_ports:
        print("No common ports fall within this range.")
        return 0, [], {}, {}

    # Initialize local variables
    open_ports = []
    port_to_banner = {}
    port_to_time = {}

    start_total_time = time.time()

    for port in scan_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                start_time = time.time()
                sock.settimeout(5)
                connection = sock.connect_ex((host, port))

                if connection == 0:
                    open_ports.append(port)
                    try:
                        banner = sock.recv(1024).decode(errors="ignore").strip()
                        port_to_banner[port] = banner if banner else "Uncertain"
                    except:
                        port_to_banner[port] = "Uncertain"

                    port_to_time[port] = time.time() - start_time
        except Exception:
            continue

    total_time = time.time() - start_total_time

    print_scan_summary(open_ports, port_to_banner)
    print(f"\nScan completed in {total_time:.2f} seconds.")
    
    return total_time, open_ports, port_to_banner, port_to_time

def main():
    host_to_port_range = {}
    print("Welcome to the multi-host port scanner!")

    host, port_range = get_user_input()
    host_to_port_range[host] = port_range

    while True:
        user_choice = input("Would you like to scan another host? (y/n): ").strip().lower()
        if user_choice == "n":
            break
        elif user_choice == "y":
            host, port_range = get_user_input()
            host_to_port_range[host] = port_range
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

    entire_summary_list = []

    for host, port_range in host_to_port_range.items():
        print(f"\n--- Scanning {host} ---")
        scan_time, open_ports, port_to_banner, port_to_time = scan(host, port_range)

        host_summary = create_export_dict(
            host, port_range, open_ports, port_to_banner, port_to_time, scan_time
        )
        entire_summary_list.append(host_summary)

    export_json(entire_summary_list)
    
if __name__ == "__main__":
    main()
