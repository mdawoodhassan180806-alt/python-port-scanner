#!/usr/bin/env python3
"""
Simple Network Port Scanner
Scans a host for open TCP ports and reports the associated service name.

LEGAL NOTICE:
Only scan hosts/networks you own or have explicit written permission to test.
Unauthorized port scanning may violate computer misuse laws in your country.
"""

import socket
import argparse
import sys
import threading
from queue import Queue
from datetime import datetime

print_lock = threading.Lock()


def get_service_name(port, proto="tcp"):
    """Return the common service name for a port, or 'unknown'."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def scan_port(host, port, timeout, open_ports):
    """Attempt a TCP connection to a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = get_service_name(port)
                with print_lock:
                    print(f"[OPEN]   Port {port:<6} {service}")
                open_ports.append((port, service))
    except socket.gaierror:
        with print_lock:
            print(f"[ERROR] Could not resolve hostname: {host}")
        sys.exit(1)
    except socket.error:
        pass  # closed/filtered port, ignore


def worker(host, timeout, q, open_ports):
    while not q.empty():
        port = q.get()
        scan_port(host, port, timeout, open_ports)
        q.task_done()


def main():
    parser = argparse.ArgumentParser(
        description="Simple multi-threaded TCP port scanner."
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range to scan, e.g. 1-1024 or 80,443,8080 (default: 1-1024)"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help="Timeout in seconds per port (default: 1.0)"
    )
    parser.add_argument(
        "-T", "--threads", type=int, default=100,
        help="Number of concurrent threads (default: 100)"
    )
    args = parser.parse_args()

    # Resolve target hostname to IP
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[ERROR] Hostname could not be resolved: {args.target}")
        sys.exit(1)

    # Parse port range/list
    ports = []
    if "," in args.ports:
        ports = [int(p) for p in args.ports.split(",")]
    elif "-" in args.ports:
        start, end = args.ports.split("-")
        ports = list(range(int(start), int(end) + 1))
    else:
        ports = [int(args.ports)]

    print("-" * 50)
    print(f"Scanning target : {args.target} ({target_ip})")
    print(f"Port range      : {args.ports}")
    print(f"Started at      : {datetime.now()}")
    print("-" * 50)

    q = Queue()
    for port in ports:
        q.put(port)

    open_ports = []
    threads = []
    num_threads = min(args.threads, len(ports))

    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(target_ip, args.timeout, q, open_ports))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    print("-" * 50)
    print(f"Scan completed at: {datetime.now()}")
    print(f"Open ports found : {len(open_ports)}")
    print("-" * 50)


if __name__ == "__main__":
    main()
