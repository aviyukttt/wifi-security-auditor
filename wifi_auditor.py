#!/usr/bin/env python3
"""Local, defensive Wi-Fi security auditor.

This app performs read-only Wi-Fi discovery through nmcli when available and
checks a password locally for common weakness signals. It never attempts to
authenticate, submit passwords, or alter network state.
"""
from __future__ import annotations

import shutil
import subprocess
import threading
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from wifi_core import password_findings


@dataclass
class Network:
    ssid: str
    security: str
    signal: str
    channel: str


def scan_networks(stop_event: threading.Event) -> list[Network]:
    """Run a bounded, read-only nmcli scan. No connection command is used."""
    if not shutil.which("nmcli"):
        raise RuntimeError("nmcli is not installed. Install NetworkManager to enable discovery.")
    cmd = ["nmcli", "-t", "-f", "SSID,SECURITY,SIGNAL,CHAN", "device", "wifi", "list", "--rescan", "no"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError("The read-only scan timed out after 20 seconds.")
    if stop_event.is_set():
        return []
    if proc.returncode != 0:
        raise RuntimeError(stderr.strip() or "nmcli could not read nearby Wi-Fi information.")
    networks: list[Network] = []
    for row in stdout.splitlines():
        parts = row.split(":")
        if len(parts) < 4:
            continue
        ssid, security, signal, channel = [part.replace("\\:", ":").strip() for part in parts[:4]]
        networks.append(Network(ssid or "(hidden SSID)", security or "OPEN/unknown", signal or "?", channel or "?"))
    return networks


class Auditor(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Wi-Fi Security Auditor")
        self.geometry("820x620")
        self.minsize(700, 500)
        self.stop_event = threading.Event()
        self._build_ui()

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=16)
        root.pack(fill="both", expand=True)
        ttk.Label(root, text="Wi-Fi Security Auditor", font=("TkDefaultFont", 18, "bold")).pack(anchor="w")
        ttk.Label(root, text="Read-only local checks for networks you own. This tool never guesses passwords or connects automatically.", wraplength=760).pack(anchor="w", pady=(4, 14))

        scan_frame = ttk.LabelFrame(root, text="Nearby network visibility (read-only)", padding=10)
        scan_frame.pack(fill="both", expand=True)
        buttons = ttk.Frame(scan_frame)
        buttons.pack(fill="x", pady=(0, 8))
        self.scan_button = ttk.Button(buttons, text="Scan (max 20 seconds)", command=self.start_scan)
        self.scan_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=8)
        self.status = ttk.Label(buttons, text="Idle")
        self.status.pack(side="left", padx=8)
        columns = ("ssid", "security", "signal", "channel")
        self.tree = ttk.Treeview(scan_frame, columns=columns, show="headings", height=8)
        for col, title, width in (("ssid", "SSID", 290), ("security", "Security", 190), ("signal", "Signal", 90), ("channel", "Channel", 90)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)

        pass_frame = ttk.LabelFrame(root, text="Local passphrase check", padding=10)
        pass_frame.pack(fill="x", pady=(14, 0))
        row = ttk.Frame(pass_frame)
        row.pack(fill="x")
        self.password = tk.StringVar()
        self.pass_entry = ttk.Entry(row, textvariable=self.password, show="•")
        self.pass_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Check locally", command=self.check_password).pack(side="left", padx=(8, 0))
        self.pass_result = ttk.Label(pass_frame, text="Your passphrase stays in this process and is not saved or transmitted.", wraplength=760)
        self.pass_result.pack(anchor="w", pady=(8, 0))
        self.findings = ScrolledText(pass_frame, height=5, wrap="word", state="disabled")
        self.findings.pack(fill="x", pady=(8, 0))

        ttk.Label(root, text="Hardening: prefer WPA3/WPA2, disable WPS, update firmware, change default admin credentials, and review connected devices.", wraplength=760).pack(anchor="w", pady=(12, 0))

    def start_scan(self) -> None:
        self.stop_event.clear()
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status.configure(text="Scanning read-only…")
        for item in self.tree.get_children():
            self.tree.delete(item)
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def stop_scan(self) -> None:
        self.stop_event.set()
        self.status.configure(text="Stopping…")
        self.stop_button.configure(state="disabled")

    def _scan_worker(self) -> None:
        try:
            networks = scan_networks(self.stop_event)
            self.after(0, lambda: self._scan_done(networks))
        except Exception as exc:
            self.after(0, lambda: self._scan_error(str(exc)))

    def _scan_done(self, networks: list[Network]) -> None:
        if self.stop_event.is_set():
            self.status.configure(text="Stopped")
        else:
            for network in networks:
                self.tree.insert("", "end", values=(network.ssid, network.security, network.signal, network.channel))
            self.status.configure(text=f"Done — {len(networks)} network(s) listed")
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def _scan_error(self, error: str) -> None:
        self.status.configure(text="Scan failed")
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        messagebox.showerror("Read-only scan", error)

    def check_password(self) -> None:
        password = self.password.get()
        if not password:
            self.pass_result.configure(text="Enter a passphrase to check locally.")
            return
        label, tips = password_findings(password)
        # Display only a local result; do not log, save, hash, or transmit the secret.
        self.pass_result.configure(text=f"Assessment: {label} | Length: {len(password)} characters")
        self.findings.configure(state="normal")
        self.findings.delete("1.0", "end")
        self.findings.insert("end", "\n".join(f"• {tip}" for tip in tips))
        self.findings.configure(state="disabled")


if __name__ == "__main__":
    Auditor().mainloop()
