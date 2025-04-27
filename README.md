# Simple Network & Wi-Fi Analyzer (for Windows)

I really dont care what you do with this

## Features

* **IP & Port Scanner:** Scan a target IP address for open TCP ports within a specified range.
* **Ping Tool:** Send ICMP echo requests (pings) to a target IP address and display the responses.
* **Wi-Fi SSID Lister:** List available Wi-Fi network names (SSIDs) in your vicinity (Windows only).
* **TCP Handshake Simulator:** Attempt a TCP connection to a specific IP and port and log the steps of the 3-way handshake (SYN, SYN-ACK, ACK).
* **Graphical User Interface (GUI):** Easy-to-use window built with Tkinter.
* **Threading:** Network operations run in separate threads to keep the GUI responsive.
* **Copy SSID:** Right-click on text in the output area (like an SSID) to copy it to the clipboard.
  
## Getting Started

These instructions will get you a copy of the project up and running on your local Windows machine.

### Prerequisites
    Python: The script requires a Python interpreter. Python 3.6 or later is recommended. You can download Python from python.org.
    Standard Libraries: Most of the necessary modules (subprocess, socket, threading, time, tkinter, re, platform, queue, ipaddress, json, http.client, ssl, urllib.parse) are part of Python's standard library and are included with a standard Python installation. No additional installation is needed for these.
    Third-Party Libraries: The script uses the pyperclip library, which is not included in Python's standard library. You need to install it separately.

    ```bash
    pip install pyperclip
    ```

### Installation

1.  Clone this repository or download the source code file (`netscan.py`) to your local machine.
    ```bash
    # If using git
    git clone <repository_url>
    cd <repository_folder>
    ```

### Running the Tool

1.  Open your command prompt.
2.  Navigate to the directory where you saved the script.
3.  Run the script using Python:
    ```bash
    python netscan.py

## Usage

The tool provides a simple GUI:

1.  **IP & Port Scanner / Ping Tool:**
    * Enter the target IP address in the "Target IP" field.
    * For Port Scanning, enter the port range (e.g., `1-100`) in the "Port Range" field.
    * Click "Start Port Scan" to scan for open TCP ports.
    * Click "Start Ping (4 packets)" to send 4 ping requests to the target IP.
    * Click "Simulate TCP Handshake" to attempt and log the connection process to the first port in the "Port Range" field.
2.  **Wi-Fi SSID Lister:**
    * Click "List SSIDs" to display available Wi-Fi network names in the output area (Windows only).
3.  **Output Area:**
    * Results from all operations will appear in the large text area.
    * You can select text in this area (like an SSID or an IP) and right-click to "Copy Selected Text".
4.  **Stop Current Operation:**
    * Click the "Stop Current Operation" button to attempt to halt the currently running scan, ping, or handshake simulation.

## Future Enhancements (Ideas)

* Add options for continuous ping or specifying the number of pings.
* Implement more detailed service banner grabbing.
* Add UDP scanning capabilities.
* Allow scanning a range of IP addresses.
* Improve error handling and user input validation.
* Add options to save scan results to a file.
* Include a "Stop" button specific to each operation.
