import socket
import time
from constants import COMMON_PORTS

def scan(host, port_range):
    start_port, end_port = map(int, port_range.split("-"))
    scan_ports = [port for port in COMMON_PORTS if start_port <= port <= end_port]

    if not scan_ports:
        print("No common ports fall within this range.")
        return 0, [], {}, {}

    open_ports = []
    port_to_banner = {}
    port_to_time = {}
    start_total_time = time.time()

    for port in scan_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                start_time = time.time()
                sock.settimeout(5)
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

    total_time = time.time() - start_total_time
    print(f"\nScan completed in {total_time:.2f} seconds.")
    return total_time, open_ports, port_to_banner, port_to_time

def create_export_dict(host, port_range, open_ports, port_to_banner, port_to_time, total_time):
    from constants import COMMON_PORTS
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
