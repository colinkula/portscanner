import argparse
from scanner import PortScanner
from validator import get_valid_host_and_range
from utils import export_json

from strategies.basic import BasicConnectionScan
# from strategies.fragmented import FragmentedScan
# from strategies.decoy import DecoyScan

def get_strategy(name, min_delay, max_delay):
    if name == "basic":
        return BasicConnectionScan(min_delay=min_delay, max_delay=max_delay)
    # elif name == "fragmented":
    #     return FragmentedScan(...)
    # elif name == "decoy":
    #     return DecoyScan(...)
    else:
        raise ValueError(f"Unsupported strategy: {name}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Multi-Host Port Scanner")
    parser.add_argument(
        "--hosts",
        nargs = "+",
        help = "List of hosts to scan."
    )
    parser.add_argument(
        "--ranges",
        nargs = "+",
        help = "List of port ranges to scan. Either one range for all hosts or one per host."
    )
    parser.add_argument(
        "--strategy", choices=["basic"], default="basic",
        help="Scanning strategy to use (e.g., basic, decoy, fragmented)."
    )
    parser.add_argument(
        "--shuffle", action="store_true", help="Randomize the order of port scanning."
    )
    parser.add_argument(
        "--min-delay", type=float, default=0, help="Minimum delay between scans (seconds)."
    )
    parser.add_argument(
        "--max-delay", type=float, default=0, help="Maximum delay between scans (seconds)."
    )

    return parser.parse_args()

def handle_cli_mode(hosts, ranges, strategy, shuffle):
    results = []
    num_hosts = len(hosts)
    num_ranges = len(ranges)

    if num_ranges == 1:
        port_ranges = [ranges[0]] * num_hosts
    elif num_hosts == num_ranges:
        port_ranges = ranges
    else:
        print("Error: Number of ranges must be 1 or match number of hosts.")
        return []
    
    for host, port_range in zip(hosts, port_ranges):
        print(f"--- Scanning {host} ---")
        scanner = PortScanner(
            host=host,
            port_range=port_range,
            strategy=strategy,
            shuffle_ports=shuffle,
        )
        summary = scanner.scan()
        results.append(summary)

    return results

def handle_interactive_mode(strategy, shuffle):
    print("Welcome to the Multi-Host Port Scanner!")
    results = {}
    
    while True:
        result = get_valid_host_and_range()
        if not result:
            break

        host, port_range = result
        results[host] = port_range

        again = input("Would you like to scan another host? (y/n): ").strip().lower()
        if again != 'y':
            break

    scan_summaries = []
    for host, port_range in results.items():
        print(f"\n--- Scanning {host} ---")
        scanner = PortScanner(
            host = host,
            port_range = port_range,
            strategy = strategy,
            shuffle_ports = shuffle
        )
        summary = scanner.scan()
        scan_summaries.append(summary)

    return scan_summaries

def main():
    args = parse_arguments()
    strategy = get_strategy(args.strategy, args.min_delay, args.max_delay)

    if args.hosts and args.ranges:
        results = handle_cli_mode(args.hosts, args.ranges, strategy, args.shuffle)
    else:
        results = handle_interactive_mode(strategy, args.shuffle)

    if results:
        export_json(results)

if __name__ == "__main__":
    main()
