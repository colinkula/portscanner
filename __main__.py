from io_handler import get_user_input, print_scan_summary, export_json
from scanner import scan, create_export_dict
import sys

def main():
    host_to_port_range = {}
    print("Welcome to the multi-host port scanner!")

    user_input = get_user_input()
    if not user_input:
        sys.exit()

    host, port_range = user_input
    host_to_port_range[host] = port_range

    while True:
        user_choice = input("Would you like to scan another host? (y/n): ").strip().lower()
        if user_choice == "n":
            break
        elif user_choice == "y":
            user_input = get_user_input()
            if not user_input:
                break
            host, port_range = user_input
            host_to_port_range[host] = port_range
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

    entire_summary_list = []

    for host, port_range in host_to_port_range.items():
        print(f"\n--- Scanning {host} ---")
        scan_time, open_ports, port_to_banner, port_to_time = scan(host, port_range)
        print_scan_summary(open_ports, port_to_banner)

        host_summary = create_export_dict(
            host, port_range, open_ports, port_to_banner, port_to_time, scan_time
        )
        entire_summary_list.append(host_summary)

    export_json(entire_summary_list)

if __name__ == "__main__":
    main()
