import socket, time, random
from utils import get_banner
from constants import COMMON_PORTS
from .base import ScanStrategy

class BasicConnectionScan(ScanStrategy):
    def __init__(self, timeout = 0.5, min_delay = 0, max_delay = 0):
        self.timeout = timeout
        self.min_delay = min_delay
        self.max_delay = max_delay

    def scan(self, host, port):
        if self.min_delay or self.max_delay:
            time.sleep(random.uniform(self.min_delay, self.max_delay))

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                t0 = time.time()
                result = sock.connect_ex((host, port))
                duration = time.time() - t0

                if result == 0:
                    banner = get_banner(sock)
                    return port, {
                        "service": COMMON_PORTS.get(port, "Unknown"),
                        "banner": banner,
                        "execution_time": round(duration, 2),
                        "status": "OPEN"
                    }
        except Exception:
            return None
        return None
