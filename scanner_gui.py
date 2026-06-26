#!/usr/bin/env python3
"""
Simple Network Port Scanner - GUI Version
Built with Tkinter (Python standard library)

LEGAL NOTICE:
Only scan hosts/networks you own or have explicit written permission to test.
Unauthorized port scanning may violate computer misuse laws in your country.
"""

import socket
import threading
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime


class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Port Scanner")
        self.root.geometry("650x560")
        self.root.resizable(False, False)

        self.scan_thread = None
        self.stop_flag = threading.Event()
        self.result_queue = queue.Queue()
        self.open_count = 0

        self.build_ui()
        self.poll_queue()

    # ---------- UI Layout ----------
    def build_ui(self):
        pad = {"padx": 8, "pady": 5}

        frame_top = ttk.LabelFrame(self.root, text="Scan Settings")
        frame_top.pack(fill="x", **pad)

        # Target
        ttk.Label(frame_top, text="Target (IP/Hostname):").grid(row=0, column=0, sticky="w", **pad)
        self.target_entry = ttk.Entry(frame_top, width=25)
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.grid(row=0, column=1, **pad)

        # Port range
        ttk.Label(frame_top, text="Ports (e.g. 1-1024 or 22,80,443):").grid(row=1, column=0, sticky="w", **pad)
        self.ports_entry = ttk.Entry(frame_top, width=25)
        self.ports_entry.insert(0, "1-1024")
        self.ports_entry.grid(row=1, column=1, **pad)

        # Timeout
        ttk.Label(frame_top, text="Timeout (sec):").grid(row=2, column=0, sticky="w", **pad)
        self.timeout_entry = ttk.Entry(frame_top, width=10)
        self.timeout_entry.insert(0, "1.0")
        self.timeout_entry.grid(row=2, column=1, sticky="w", **pad)

        # Threads
        ttk.Label(frame_top, text="Threads:").grid(row=3, column=0, sticky="w", **pad)
        self.threads_entry = ttk.Entry(frame_top, width=10)
        self.threads_entry.insert(0, "100")
        self.threads_entry.grid(row=3, column=1, sticky="w", **pad)

        # Buttons
        frame_btn = ttk.Frame(self.root)
        frame_btn.pack(fill="x", **pad)

        self.start_btn = ttk.Button(frame_btn, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(frame_btn, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.clear_btn = ttk.Button(frame_btn, text="Clear Output", command=self.clear_output)
        self.clear_btn.pack(side="left", padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=8, pady=5)

        # Status label
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(self.root, textvariable=self.status_var).pack(anchor="w", padx=8)

        # Output box
        frame_out = ttk.LabelFrame(self.root, text="Results")
        frame_out.pack(fill="both", expand=True, padx=8, pady=8)

        self.output = scrolledtext.ScrolledText(frame_out, wrap="word", font=("Consolas", 10))
        self.output.pack(fill="both", expand=True)
        self.output.tag_config("open", foreground="green")
        self.output.tag_config("error", foreground="red")
        self.output.tag_config("info", foreground="blue")

    # ---------- Helpers ----------
    def log(self, msg, tag=None):
        self.output.insert("end", msg + "\n", tag)
        self.output.see("end")

    def clear_output(self):
        self.output.delete("1.0", "end")

    def parse_ports(self, port_str):
        ports = []
        if "," in port_str:
            ports = [int(p.strip()) for p in port_str.split(",")]
        elif "-" in port_str:
            start, end = port_str.split("-")
            ports = list(range(int(start), int(end) + 1))
        else:
            ports = [int(port_str.strip())]
        return ports

    def get_service_name(self, port):
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

    # ---------- Scan Control ----------
    def start_scan(self):
        target = self.target_entry.get().strip()
        port_str = self.ports_entry.get().strip()

        try:
            ports = self.parse_ports(port_str)
        except ValueError:
            messagebox.showerror("Input Error", "Invalid port format. Use e.g. 1-1024 or 22,80,443")
            return

        try:
            timeout = float(self.timeout_entry.get())
            num_threads = int(self.threads_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Timeout and Threads must be numeric.")
            return

        if not target:
            messagebox.showerror("Input Error", "Target host is required.")
            return

        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            messagebox.showerror("Resolve Error", f"Could not resolve hostname: {target}")
            return

        self.clear_output()
        self.open_count = 0
        self.stop_flag.clear()
        self.progress["value"] = 0
        self.progress["maximum"] = len(ports)

        self.log(f"Target: {target} ({target_ip})", "info")
        self.log(f"Ports: {port_str}  |  Timeout: {timeout}s  |  Threads: {num_threads}", "info")
        self.log(f"Started at: {datetime.now()}", "info")
        self.log("-" * 50)

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Scanning...")

        self.scan_thread = threading.Thread(
            target=self.run_scan, args=(target_ip, ports, timeout, num_threads), daemon=True
        )
        self.scan_thread.start()

    def stop_scan(self):
        self.stop_flag.set()
        self.status_var.set("Stopping...")

    def run_scan(self, target_ip, ports, timeout, num_threads):
        q = queue.Queue()
        for p in ports:
            q.put(p)

        lock = threading.Lock()
        scanned_counter = {"count": 0}

        def worker():
            while not q.empty() and not self.stop_flag.is_set():
                try:
                    port = q.get_nowait()
                except queue.Empty:
                    return
                self.scan_port(target_ip, port, timeout)
                with lock:
                    scanned_counter["count"] += 1
                    self.result_queue.put(("progress", scanned_counter["count"]))
                q.task_done()

        threads = []
        for _ in range(min(num_threads, len(ports))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.result_queue.put(("done", None))

    def scan_port(self, target_ip, port, timeout):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    service = self.get_service_name(port)
                    self.result_queue.put(("open", (port, service)))
        except socket.error:
            pass

    # ---------- Queue Polling (keeps GUI thread-safe) ----------
    def poll_queue(self):
        try:
            while True:
                kind, data = self.result_queue.get_nowait()
                if kind == "open":
                    port, service = data
                    self.open_count += 1
                    self.log(f"[OPEN]   Port {port:<6} {service}", "open")
                elif kind == "progress":
                    self.progress["value"] = data
                elif kind == "done":
                    self.log("-" * 50)
                    self.log(f"Scan completed at: {datetime.now()}", "info")
                    self.log(f"Open ports found: {self.open_count}", "info")
                    self.status_var.set(f"Done — {self.open_count} open port(s) found")
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
        except queue.Empty:
            pass
        self.root.after(100, self.poll_queue)


def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
