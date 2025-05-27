import ipaddress
import re

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
        start_str, end_str = port_range.split("-")
        start = int(start_str)
        end = int(end_str)
        return 0 <= start <= 65535 and 1 <= end <= 65535 and start <= end
    except ValueError:
        return False
