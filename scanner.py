import socket, time
from constants import COMMON_PORTS
from utils import print_summary, get_banner

class PortScanner:
    def __init__(self, host, port_range):
        self.host = host
        self.start_port, self.end_port = map(int, port_range.split("-"))
        self.ports = [p for p in COMMON_PORTS if self.start_port <= p <= self.end_port]
        self.open_ports = []
        self.port_data = {}

    def scan(self):
        start_time = time.time()

        for port in self.ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    t0 = time.time()
                    result = sock.connect_ex((self.host, port))
                    duration = time.time() - t0

                    if result == 0:
                        banner = get_banner(sock)
                        self.open_ports.append(port)
                        self.port_data[port] = {
                            "service": COMMON_PORTS.get(port, "Unknown"),
                            "banner": banner,
                            "execution_time": round(duration, 2),
                            "status": "OPEN"
                        }
            except Exception:
                continue

        total_time = time.time() - start_time
        print_summary(self.host, self.open_ports, self.port_data, total_time)

        return {
            "host": self.host,
            "scanned_port_range": f"{self.start_port}-{self.end_port}",
            "total_execution_time": round(total_time, 2),
            "open_ports": self.port_data
        }
