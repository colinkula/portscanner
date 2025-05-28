from scanner import PortScanner
from validator import get_valid_host_and_range
from utils import export_json

def main():
    print("Welcome to the Multi-Host Port Scanner!")

    host_to_range = {}
    while True:
        result = get_valid_host_and_range()
        if not result:
            break
        host, port_range = result
        host_to_range[host] = port_range

        again = input("Would you like to scan another host? (y/n): ").strip().lower()
        if again != 'y':
            break

    results = []
    for host, port_range in host_to_range.items():
        print(f"\n--- Scanning {host} ---")
        scanner = PortScanner(host, port_range)
        summary = scanner.scan()
        results.append(summary)

    export_json(results)

if __name__ == "__main__":
    main()
