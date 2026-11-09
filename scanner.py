import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


def scan_port(host, port, timeout=1):
    """Return True if the port is open, False otherwise."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def get_service(port):
    """Return the common service name for a port, or 'unknown'."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def parse_ports(text):
    """Turn '80' or '1-1000' into (start, end)."""
    if "-" in text:
        start, end = text.split("-", 1)
        start, end = int(start), int(end)
    else:
        start = end = int(text)

    if not (1 <= start <= end <= 65535):
        raise argparse.ArgumentTypeError(
            "ports must be between 1 and 65535, and start must be <= end"
        )
    return start, end


def save_results(filename, host, ip, port_range, open_ports, elapsed):
    """Write the scan report to a text file."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write("Port Scan Report\n")
        f.write("================\n")
        f.write(f"Target : {host} ({ip})\n")
        f.write(f"Ports  : {port_range[0]}-{port_range[1]}\n")
        f.write(f"Date   : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"Time   : {elapsed:.2f} seconds\n\n")
        f.write("PORT        SERVICE\n")
        for port in open_ports:
            f.write(f"{str(port) + '/tcp':<11} {get_service(port)}\n")
        f.write(f"\n{len(open_ports)} open port(s) found.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Simple multithreaded TCP port scanner. "
        "Only scan machines you own or have permission to test."
    )
    parser.add_argument("host", help="target IP or hostname")
    parser.add_argument(
        "-p", "--ports", type=parse_ports, default="1-1024",
        help="port or range to scan, e.g. 80 or 1-1000 (default: 1-1024)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="number of threads (default: 100)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="seconds to wait per port (default: 1.0)",
    )
    parser.add_argument(
        "-o", "--output",
        help="save the results to a text file, e.g. results.txt",
    )
    args = parser.parse_args()

    # default is a string, so parse it when the user did not give -p
    if isinstance(args.ports, str):
        args.ports = parse_ports(args.ports)
    start_port, end_port = args.ports

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print("Could not resolve that host.")
        return

    print("=== Simple Port Scanner ===")
    print(f"Scanning {args.host} ({ip}) ports {start_port}-{end_port}\n")

    started = time.time()
    open_ports = []

    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = executor.map(
            lambda p: (p, scan_port(ip, p, args.timeout)), ports
        )

        print("PORT        SERVICE")
        for port, is_open in results:
            if is_open:
                print(f"{str(port) + '/tcp':<11} {get_service(port)}")
                open_ports.append(port)

    elapsed = time.time() - started
    print(f"\nDone in {elapsed:.2f} seconds. {len(open_ports)} open port(s) found.")

    if args.output:
        save_results(
            args.output, args.host, ip, (start_port, end_port),
            open_ports, elapsed,
        )
        print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()