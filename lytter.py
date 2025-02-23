from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from datetime import datetime
import threading
import json
from pathlib import Path
from scapy.all import *  # noqa: F403
import tomllib
import time
from collections import deque

IPV4 = "ipv4"
MAC = "mac"
DEVICE_HISTORY_FILE = "device_history.json"

console = Console()


class NetworkScanner:
    def __init__(self):
        self.found = {IPV4: [], MAC: []}
        self.whitelisted = {IPV4: [], MAC: []}
        self.device_history = self.load_device_history()
        self.active_devices = []
        self.packets_captured = 0
        self.scan_start_time = datetime.now()
        self.messages = deque(maxlen=5)
        self.DEVICE_TIMEOUT = 10

    def generate_display(self) -> Layout:
        layout = Layout()

        layout.split_column(Layout(name="table"), Layout(name="messages", size=8))
        layout["table"].update(self.generate_table())
        messages_panel = Panel(
            "\n".join(self.messages),
            title="[#565f89]Messages[/#565f89]",
            border_style="#565f89",
            padding=(0, 1),
        )
        layout["messages"].update(messages_panel)

        return layout

    def check_inactive_devices(self):
        now = datetime.now()
        new_active_devices = []

        for device in self.device_history["devices"]:
            last_seen = datetime.strptime(device["last_seen"], "%Y-%m-%d %H:%M:%S")
            time_diff = (now - last_seen).total_seconds()

            if time_diff < self.DEVICE_TIMEOUT:
                new_active_devices.append(device["ip"])
            else:
                if device["ip"] in self.active_devices:
                    self.add_message(
                        f"[#f7768e]Device disconnected: {device['ip']} ({device['mac']})[/#f7768e]"
                    )

        self.active_devices = new_active_devices

    def generate_table(self) -> Panel:
        table = Table(
            show_header=True,
            header_style="bold #7aa2f7",
            expand=True,
            show_edge=True,
            box=None,
            padding=(0, 1),
        )

        table.add_column("IP", style="#a9b1d6", width=15)
        table.add_column("MAC", style="#a9b1d6", width=17)
        table.add_column("First Seen", style="#565f89", width=16)
        table.add_column("Last Seen", style="#565f89", width=16)
        table.add_column("Status", style="bold", width=8)

        if not self.device_history["devices"]:
            table.add_row("[#565f89]Waiting for devices...[/#565f89]", "", "", "", "")
        else:
            for device in self.device_history["devices"]:
                status = "●" if device["ip"] in self.active_devices else "○"
                status_color = (
                    "#9ece6a" if device["ip"] in self.active_devices else "#565f89"
                )
                table.add_row(
                    device["ip"],
                    device["mac"],
                    device["first_seen"],
                    device["last_seen"],
                    f"[{status_color}]{status}[/{status_color}]",
                )

        duration = str(datetime.now() - self.scan_start_time).split(".")[0]
        stats = f"[#565f89]Scan time: [#7aa2f7]{duration}[/#7aa2f7] • "
        stats += f"Active devices: [#7aa2f7]{len(self.active_devices)}[/#7aa2f7] • "
        stats += f"Packets: [#7aa2f7]{self.packets_captured}[/#7aa2f7][/#565f89]"

        return Panel(table, title=stats, border_style="#565f89", padding=(0, 1))

    def add_message(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.messages.append(f"[#565f89]{timestamp}[/#565f89] {message}")

    def load_device_history(self) -> dict:
        history_file = Path(DEVICE_HISTORY_FILE)
        if history_file.exists():
            try:
                with open(history_file, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {"devices": []}
        return {"devices": []}

    def save_device_history(self):
        with open(DEVICE_HISTORY_FILE, "w") as f:
            json.dump(self.device_history, f, indent=2)

    def is_device_known(self, ip: str, mac: str) -> bool:
        for device in self.device_history["devices"]:
            if device["ip"] == ip and device["mac"] == mac:
                return True
        return False

    def add_device_to_history(self, ip: str, mac: str):
        device_info = {
            "ip": ip,
            "mac": mac,
            "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }
        self.device_history["devices"].append(device_info)
        self.active_devices.append(ip)
        self.save_device_history()
        self.add_message(
            f"[#7aa2f7]► New device: [/#7aa2f7][#a9b1d6]{ip} ({mac})[/#a9b1d6]"
        )

    def update_device_last_seen(self, ip: str, mac: str):
        for device in self.device_history["devices"]:
            if device["ip"] == ip and device["mac"] == mac:
                device["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if ip not in self.active_devices:
                    self.active_devices.append(ip)
                self.save_device_history()
                break

    def arp_monitor_callback(self, pkt):
        if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
            self.packets_captured += 1
            dev_ip = pkt.sprintf("%ARP.psrc%")
            dev_mac = pkt.sprintf("%ARP.hwsrc%")

            self.add_message(
                f"[#565f89]Packet detected - IP: {dev_ip}, MAC: {dev_mac}[/#565f89]"
            )

            if dev_ip in self.whitelisted[IPV4] or dev_mac in self.whitelisted[MAC]:
                self.add_message(
                    f"[#565f89]Skipping whitelisted device: {dev_ip}[/#565f89]"
                )
                return

            if not self.is_device_known(dev_ip, dev_mac):
                if dev_ip not in self.found[IPV4]:
                    self.found[IPV4].append(dev_ip)
                    self.found[MAC].append(dev_mac)
                    self.add_device_to_history(dev_ip, dev_mac)
            else:
                self.update_device_last_seen(dev_ip, dev_mac)

    def whitelist_file(self):
        try:
            with open("config.toml", "rb") as f:
                config = tomllib.load(f)
                self.whitelisted[IPV4] = config["whitelisted"][IPV4]
                self.whitelisted[MAC] = config["whitelisted"][MAC]
        except FileNotFoundError:
            self.add_message(
                "[#f7768e]No config.toml found. No devices whitelisted.[/#f7768e]"
            )
            self.whitelisted = {IPV4: [], MAC: []}


def refresh_display(scanner, live):
    while True:
        time.sleep(1)
        scanner.check_inactive_devices()
        scanner.found = {IPV4: [], MAC: []}
        live.update(scanner.generate_display())


def main():
    scanner = NetworkScanner()
    scanner.whitelist_file()

    scanner.add_message("[#565f89]Starting network scan...[/#565f89]")

    with Live(
        scanner.generate_display(), refresh_per_second=2, screen=False, transient=True
    ) as live:
        threading.Thread(
            target=refresh_display, args=(scanner, live), daemon=True
        ).start()

        try:
            sniff(prn=scanner.arp_monitor_callback, filter="arp", store=0)  # noqa: F405
        except KeyboardInterrupt:
            scanner.add_message("[#f7768e]Scan terminated by user[/#f7768e]")
            scanner.save_device_history()


if __name__ == "__main__":
    main()
