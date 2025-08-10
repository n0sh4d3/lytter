# Lytter – Network Scanner

**Lytter** is a terminal-based network scanning and device tracking tool with a clean TUI (text user interface).  
It’s built to identify active devices on your local network, track them over time, and allow whitelisting of devices you don’t want to scan.

> ⚠️ **Disclaimer:** This project is experimental. It works most of the time, but occasional instability and unhandled edge cases may occur. Consider it a work in progress.

---

## Overview

Lytter scans your network and attempts to detect connected devices in real-time.  
It uses packet sniffing to gather IP and MAC addresses, displays them in a TUI, and saves device history for later analysis.  
You can whitelist devices to skip in future scans.

---

## Features

- Clean terminal UI (TUI)
- Scans your network for active devices
- Displays IP and MAC addresses in real-time
- Tracks device history in `device_history.json`
- Allows whitelisting of devices you want to skip
- Configurable via `config.toml`

---

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/n0sh4d3/lytter.git
    cd lytter
    ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Ensure your system supports packet sniffing (may require elevated privileges).

---

## Usage

Run the scanner:
```bash
python lytter.py
````

The UI will update every second with detected devices.
If the UI freezes or becomes unresponsive, you can restart the tool.

---

## Configuration

* **`config.toml`** – Configure settings such as device whitelisting.
* **`device_history.json`** – Stores historical scan data (more reliable than the live UI for long-term tracking).

---

## Known Issues

* The TUI may occasionally freeze or fail to refresh.
* Some devices may not appear in the UI but will be recorded in `device_history.json`.
* Occasional crashes due to unhandled edge cases.
* Restarting the application usually resolves temporary issues.

---

## License

This project is open-source.
Feel free to fork, modify, or repurpose it for your own needs.

