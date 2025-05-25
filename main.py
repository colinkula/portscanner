import ipaddress
import socket
import re
import time

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
        port_range = input("Enter the port range (Format: numbers 0-65535 to 1-65535 | Example: 0-1024): ")
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
        print("----- IP is valid")
        return True
    
    print("----- IP is invalid, trying domain name...")
    try:
        if is_valid_domain_name(host):
            IP = socket.gethostbyname(host)
            print(f"----- IP found! ({IP})")
            return True
        else:
            print("----- domain name is invalid")
    except socket.error:
        print("----- error with domain name validation!")
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
        print("----- missing hyphen (-) in response")
        return False
    
    try:
        start_str, end_str = port_range.split("-")
        start_num = int(start_str)
        end_num = int(end_str)
        if 0 <= start_num <= 65535 and 1 <= end_num <= 65535 and start_num <= end_num:
            print("----- port range is valid\n")
            return True
    except ValueError:
        return False

    return False

def scan(host,port_range):
    print(f"Scan initiated for {host} in range {port_range}")
    start_port, end_port = port_range.split("-")
    open_ports = []
    start_time = time.time()

    # Loop all ports
    for port in range(int(start_port), int(end_port) + 1):
        # Initialize socket with family and socket type: IPV4 and TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        connection = sock.connect_ex((host,port))

        # Connected
        if connection == 0:
            open_ports.append(port)

    end_time = time.time()
    elapsed_time = end_time - start_time

    print(f"Open Ports: ")
    for port in open_ports:
        print(f" - {port} ({COMMON_PORTS.get(port, 'Unknown Service')})")
    print(f"Scan completed in {elapsed_time:.3f} seconds.")

host, port_range = get_user_input()
scan(host, port_range)