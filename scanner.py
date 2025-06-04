from concurrent.futures import ThreadPoolExecutor, as_completed
import time, random
from constants import COMMON_PORTS
from utils import print_summary

class PortScanner:
    def __init__(self, host, port_range, strategy, shuffle_ports=True, max_threads=100):
        self.host = host
        self.strategy = strategy
        self.start_port, self.end_port = map(int, port_range.split("-"))
        self.ports = [p for p in COMMON_PORTS if self.start_port <= p <= self.end_port]
        
        if shuffle_ports:
            random.shuffle(self.ports)

        self.max_threads = min(max_threads, len(self.ports))
        
        self.open_ports = []
        self.port_data = {}

    def scan(self):
        start_time = time.time()
        max_threads = min(100, len(self.ports))

        with ThreadPoolExecutor(max_workers = max_threads) as executor:
            future_to_port = {executor.submit(self.strategy.scan, self.host, port): port for port in self.ports}

            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    port, data = result
                    self.open_ports.append(port)
                    self.port_data[port] = data

        total_time = time.time() - start_time
        print_summary(self.host, self.open_ports, self.port_data, total_time)

        return {
            "host": self.host,
            "scanned_port_range": f"{self.start_port}-{self.end_port}",
            "total_execution_time": round(total_time, 2),
            "open_ports": self.port_data
        }
