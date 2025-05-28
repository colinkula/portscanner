import ipaddress, re

def get_valid_host_and_range():
    while True:
        host = input("Enter host (IP or domain) [or 'q' to quit]: ").strip()
        if host == "q":
            return None
        if validate_host(host):
            break
        print("Invalid host.")

    while True:
        port_range = input("Enter port range (e.g., 0-1024) [or 'q' to quit]: ").strip()
        if port_range == "q":
            return None
        if validate_port_range(port_range):
            return host, port_range
        print("Invalid port range.")

def validate_host(host):
    return is_ip(host) or is_domain(host)

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def is_domain(host):
    return re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", host)
    
def validate_port_range(rng):
    if "-" not in rng:
        return False
    try:
        s, e = map(int, rng.split("-"))
        return 0 <= s <= e <= 65535
    except:
        return False
