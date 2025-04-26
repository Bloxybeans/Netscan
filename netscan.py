import subprocess
import socket
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, END, messagebox, ttk # Import ttk widgets
import re
import platform
import pyperclip

# --- Configuration ---
SOCKET_TIMEOUT = 1
MAX_THREADS = 50

# --- GUI Class ---
class NetworkScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Simple Network & Wi-Fi Analyzer")

        # Use a ttk Style for potential future styling
        self.style = ttk.Style()
        # Optional: self.style.theme_use('clam') # Try different themes like 'clam', 'alt', 'default', 'classic'

        # Make the main window resizable
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(2, weight=1) # Make output area expand vertically

        # --- IP/Port Scanner & Ping Tool Frame ---
        # Use ttk.LabelFrame for a themed look
        ip_port_frame = ttk.LabelFrame(master, text="IP & Port Scanner / Ping Tool", padding=(10, 10))
        ip_port_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ip_port_frame.grid_columnconfigure(1, weight=1) # Make IP entry column expand

        # --- Input Widgets (using ttk where available) ---
        self.label_ip = ttk.Label(ip_port_frame, text="Target IP:")
        self.label_ip.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.entry_ip = ttk.Entry(ip_port_frame, width=30)
        self.entry_ip.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.entry_ip.insert(0, "127.0.0.1") # Default IP

        self.label_ports = ttk.Label(ip_port_frame, text="Port Range (e.g., 1-100):")
        self.label_ports.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.entry_ports = ttk.Entry(ip_port_frame, width=30)
        self.entry_ports.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.entry_ports.insert(0, "1-100") # Default Port Range

        # --- Buttons for IP/Port Scan, Ping, and Handshake ---
        self.scan_button = ttk.Button(ip_port_frame, text="Start Port Scan", command=self.start_ip_port_scan_thread)
        self.scan_button.grid(row=2, column=0, pady=10, sticky="ew")

        self.ping_button = ttk.Button(ip_port_frame, text="Start Ping (4 packets)", command=self.start_ping_thread)
        self.ping_button.grid(row=2, column=1, pady=10, padx=(5,0), sticky="ew")

        self.handshake_button = ttk.Button(ip_port_frame, text="Simulate TCP Handshake", command=self.start_handshake_thread)
        self.handshake_button.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")


        # --- SSID Lister Frame ---
        ssid_frame = ttk.LabelFrame(master, text="Wi-Fi SSID Lister (Windows Only)", padding=(10, 10))
        ssid_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        ssid_frame.grid_columnconfigure(0, weight=1) # Make column expandable

        # --- SSID Scan Button ---
        self.ssid_scan_button = ttk.Button(ssid_frame, text="List SSIDs", command=self.start_ssid_scan_thread)
        self.ssid_scan_button.grid(row=0, column=0, pady=5, sticky="ew")


        # --- Output Text Area (Shared) ---
        self.output_area = scrolledtext.ScrolledText(master, width=60, height=15, wrap=tk.WORD)
        self.output_area.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        self.output_area.config(state='normal') # Keep it normal state to allow selection
        self.output_area.bind("<Button-3>", self.show_context_menu) # Bind right-click

        # --- Context Menu ---
        self.context_menu = tk.Menu(master, tearoff=0)
        self.context_menu.add_command(label="Copy Selected Text", command=self.copy_selected_text)
        # You could add more options here later, e.g., "Use Selected as Target IP"

        # --- Status Label ---
        self.status_label = ttk.Label(master, text="Ready.", relief=tk.SUNKEN, anchor=tk.W) # ttk Label doesn't have bd, use relief
        self.status_label.grid(row=3, column=0, sticky="ew", padx=5, pady=2)

        # --- Stop Button ---
        stop_button = ttk.Button(master, text="Stop Current Operation", command=self.stop_operation)
        stop_button.grid(row=4, column=0, pady=5)

        # --- Threading Variables ---
        self.current_thread = None
        self.stop_event = threading.Event()


    # --- Context Menu Functions ---
    def show_context_menu(self, event):
        """Displays the context menu at the mouse position."""
        try:
            # Ensure there is text selected before showing copy option (optional)
            if self.output_area.tag_ranges(tk.SEL):
                 self.context_menu.entryconfig("Copy Selected Text", state="normal")
            else:
                 self.context_menu.entryconfig("Copy Selected Text", state="disabled")

            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def copy_selected_text(self):
        """Copies the currently selected text from the output area to the clipboard."""
        try:
            selected_text = self.output_area.get(tk.SEL_FIRST, tk.SEL_LAST)
            if selected_text:
                pyperclip.copy(selected_text)
                self.update_status("Selected text copied to clipboard.")
            else:
                 self.update_status("No text selected.")
        except tk.TclError:
            self.update_status("No text selected.")
        except Exception as e:
            self.update_output(f"Error copying text: {e}")


    # --- Helper to update the GUI text area safely from another thread ---
    def update_output(self, message):
        self.master.after(0, self._perform_update_output, message)

    def _perform_update_output(self, message):
         self.output_area.insert(END, message + "\n")
         self.output_area.see(END)


    # --- Helper to update the status label safely ---
    def update_status(self, message):
         self.master.after(0, self._perform_update_status, message)

    def _perform_update_status(self, message):
         self.status_label.config(text=message)

    # --- Helper to disable/enable buttons ---
    def set_button_state(self, state):
         self.scan_button.config(state=state)
         self.ping_button.config(state=state)
         self.handshake_button.config(state=state)
         if platform.system() == "Windows" or state == 'disabled':
             self.ssid_scan_button.config(state=state)


    # --- Wrappers to start threads ---
    def start_ip_port_scan_thread(self):
        # ... (Validation, checks for active thread, clears output, sets button state, starts run_ip_port_scan) ...
        target_ip = self.entry_ip.get()
        port_range_str = self.entry_ports.get()

        if not target_ip or not port_range_str:
             messagebox.showwarning("Input Error", "Please enter target IP and port range.")
             return

        try:
            start_port, end_port = map(int, port_range_str.split('-'))
            if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
                 raise ValueError("Invalid port range values.")
        except ValueError as e:
            messagebox.showwarning("Input Error", f"Invalid port range format. Use start-end (e.g., 1-1024). {e}")
            return

        if self.current_thread and self.current_thread.is_alive():
             self.update_status("Another operation already in progress...")
             return

        self.output_area.config(state='normal')
        self.output_area.delete('1.0', END)
        self.output_area.config(state='normal')

        self.update_status("Starting IP/Port scan...")
        self.set_button_state('disabled')

        self.stop_event.clear()
        self.current_thread = threading.Thread(target=self.run_ip_port_scan, args=(target_ip, start_port, end_port))
        self.current_thread.start()


    def start_ping_thread(self):
        # ... (Validation, checks for active thread, clears output, sets button state, starts run_ping_tool) ...
        target_ip = self.entry_ip.get()

        if not target_ip:
             messagebox.showwarning("Input Error", "Please enter a target IP address to ping.")
             return

        if self.current_thread and self.current_thread.is_alive():
             self.update_status("Another operation already in progress...")
             return

        self.output_area.config(state='normal')
        self.output_area.delete('1.0', END)
        self.output_area.config(state='normal')

        self.update_status(f"Starting ping to {target_ip}...")
        self.set_button_state('disabled')

        self.stop_event.clear()
        self.current_thread = threading.Thread(target=self.run_ping_tool, args=(target_ip,))
        self.current_thread.start()

    def start_handshake_thread(self):
         # Get IP and Port for Handshake
         target_ip = self.entry_ip.get()
         port_str = self.entry_ports.get().split('-')[0] # Use the start port from the range

         if not target_ip or not port_str:
              messagebox.showwarning("Input Error", "Please enter target IP and a port for the handshake.")
              return

         try:
             target_port = int(port_str)
             if not (0 <= target_port <= 65535):
                  raise ValueError("Invalid port value.")
         except ValueError:
             messagebox.showwarning("Input Error", "Invalid port value. Please ensure the port is a number.")
             return

         if self.current_thread and self.current_thread.is_alive():
              self.update_status("Another operation already in progress...")
              return

         self.output_area.config(state='normal')
         self.output_area.delete('1.0', END)
         self.output_area.config(state='normal')

         self.update_status(f"Simulating TCP handshake with {target_ip}:{target_port}...")
         self.set_button_state('disabled')

         self.stop_event.clear()
         self.current_thread = threading.Thread(target=self.run_handshake_simulator, args=(target_ip, target_port))
         self.current_thread.start()


    def start_ssid_scan_thread(self):
         # ... (Checks OS, checks for active thread, clears output, sets button state, starts run_ssid_scan) ...
         if platform.system() != "Windows":
              messagebox.showerror("OS Error", "SSID listing with netsh is only supported on Windows.")
              return

         if self.current_thread and self.current_thread.is_alive():
              self.update_status("Another operation already in progress...")
              return

         self.output_area.config(state='normal')
         self.output_area.delete('1.0', END)
         self.output_area.config(state='normal')

         self.update_status("Starting SSID scan...")
         self.set_button_state('disabled')

         self.current_thread = threading.Thread(target=self.run_ssid_scan)
         self.current_thread.start()


    # --- Main logic to run in threads ---
    def run_ip_port_scan(self, target_ip, start_port, end_port):
        # ... (Reachability check, calls threaded_port_scan_gui, updates status/buttons) ...
        self.update_output(f"Checking host reachability for {target_ip} before port scan...")
        ping_command = ["ping", "-n", "1", "-w", "1000", target_ip]
        reachable = False
        try:
            result = subprocess.run(ping_command, capture_output=True, text=True, timeout=3, shell=True)
            if "Reply from" in result.stdout:
                self.update_output(f"{target_ip} is reachable. Proceeding with port scan.")
                reachable = True
            else:
                self.update_output(f"{target_ip} is unreachable (no reply). Cannot perform port scan.")

        except Exception as e:
            self.update_output(f"Error during reachability check for {target_ip}: {e}")
            reachable = False

        if reachable and not self.stop_event.is_set():
            self.threaded_port_scan_gui(target_ip, start_port, end_port)
        elif self.stop_event.is_set():
             self.update_output("IP/Port Scan stopped by user.")

        self.update_status("IP/Port Scan Finished.")
        self.set_button_state('normal')


    def run_ping_tool(self, target_ip, num_pings=4):
        # ... (Runs ping command, updates output line by line, checks stop_event, updates status/buttons) ...
        self.update_output(f"\nPinging {target_ip} with {num_pings} packets:")
        ping_command = ["ping", "-n", str(num_pings), "-w", "1000", target_ip]

        try:
            creationflags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            process = subprocess.Popen(ping_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, creationflags=creationflags)

            stdout_lines = iter(process.stdout.readline, '')

            while process.poll() is None and not self.stop_event.is_set():
                try:
                    line = next(stdout_lines)
                    if line:
                        self.update_output(line.strip())
                except StopIteration:
                    break

            remaining_stdout, remaining_stderr = process.communicate(timeout=0.5 if process.poll() is None else None)
            for line in remaining_stdout.splitlines():
                 if line: self.update_output(line.strip())
            for line in remaining_stderr.splitlines():
                 if line: self.update_output(f"Stderr: {line.strip()}")

            if self.stop_event.is_set():
                 self.update_output("\nPing stopped by user.")
                 if process.poll() is None:
                     try:
                         process.terminate()
                         process.wait(timeout=1)
                     except Exception:
                         pass
            else:
                 self.update_output("\nPing finished.")

        except FileNotFoundError:
            self.update_output("Error: 'ping' command not found. Make sure it's in your system's PATH.")
        except Exception as e:
            self.update_output(f"An unexpected error occurred during ping: {e}")

        self.update_status("Ping Tool Finished.")
        self.set_button_state('normal')


    def run_handshake_simulator(self, target_ip, target_port):
        """
        Simulates and logs the TCP 3-way handshake process.
        """
        self.update_output(f"\nAttempting TCP handshake with {target_ip}:{target_port}...")
        s = None # Initialize socket variable

        try:
            self.update_output("Step 1: Sending SYN packet...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)

            # Attempt to connect. If successful, the handshake completed.
            # connect_ex is used to avoid immediate exceptions on refusal.
            result = s.connect_ex((target_ip, target_port))

            if self.stop_event.is_set():
                 self.update_output("Handshake simulation stopped by user.")
                 return # Exit if stopped

            if result == 0:
                self.update_output("Step 2: Received SYN-ACK packet.")
                self.update_output("Step 3: Sending ACK packet.")
                self.update_output(f"Connection established successfully with {target_ip}:{target_port}.")
                # In a real scenario, application data exchange would happen here.
                # We can just close the connection for this simulation.
                self.update_output("Closing connection.")
                s.close()
                self.update_output("Connection closed.")
            else:
                # Handle common connection errors
                error_message = f"Connection failed. Error code: {result}"
                if result == 10061: # WSAECONNREFUSED
                    error_message += " (Connection refused)"
                elif result == 10060: # WSAETIMEDOUT
                    error_message += " (Connection timed out)"
                self.update_output(f"Handshake failed: {error_message}")


        except socket.gaierror:
            self.update_output(f"Handshake failed: Address information error (Cannot resolve hostname).")
        except socket.timeout:
             self.update_output(f"Handshake failed: Socket timeout after {SOCKET_TIMEOUT} seconds.")
        except Exception as e:
            self.update_output(f"An unexpected error occurred during handshake: {e}")

        finally:
            if s:
                s.close() # Ensure socket is closed even if errors occur

        self.update_status("TCP Handshake Simulator Finished.")
        self.set_button_state('normal')


    def run_ssid_scan(self):
        # ... (Calls list_ssids_windows_gui, updates output, updates status/buttons) ...
        self.update_output("Scanning for available Wi-Fi networks...")
        available_ssids = self.list_ssids_windows_gui()

        if available_ssids is not None:
            if available_ssids:
                self.update_output("\nAvailable Wi-Fi Networks (SSIDs):")
                for ssid in available_ssids:
                    self.update_output(f"- {ssid}")
            else:
                 if "No SSIDs found" not in self.output_area.get('1.0', END):
                      self.update_output("Could not find any available Wi-Fi networks.")

        self.update_status("SSID Scan Finished.")
        self.set_button_state('normal')


    # --- Adapted Scanning Functions ---
    # ... (scan_port_gui and threaded_port_scan_gui remain the same, check self.stop_event) ...
    def scan_port_gui(self, target_ip, port, open_ports_list):
        if self.stop_event.is_set():
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            result = s.connect_ex((target_ip, port))

            if result == 0:
                banner = ""
                try:
                    s.settimeout(0.5)
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.timeout: pass
                except Exception: pass

                output_line = f"Port {port} is open"
                if banner:
                     output_line += f" (Banner: {banner[:50]}{'...' if len(banner) > 50 else ''})"
                self.update_output(output_line)
                open_ports_list.append(port)

            s.close()

        except socket.gaierror: pass
        except socket.error: pass
        except Exception as e:
            self.update_output(f"An unexpected error occurred while scanning port {port}: {e}")

    def threaded_port_scan_gui(self, target_ip, start_port, end_port):
        open_ports = []
        threads = []

        self.update_output(f"\nScanning ports {start_port}-{end_port} on {target_ip}...")
        start_time = time.time()

        for port in range(start_port, end_port + 1):
            if self.stop_event.is_set():
                 self.update_output("IP/Port Scan interrupted.")
                 break

            while threading.active_count() > MAX_THREADS:
                time.sleep(0.01)

            thread = threading.Thread(target=self.scan_port_gui, args=(target_ip, port, open_ports))
            threads.append(thread)
            thread.start()

        for thread in threads:
             if thread.is_alive():
                thread.join(timeout=0.05)

        end_time = time.time()
        duration = end_time - start_time

        self.update_output(f"\nIP/Port Scan completed in {duration:.2f} seconds.")

        if open_ports:
            self.update_output(f"Summary of open ports: {sorted(open_ports)}")
        else:
            if not self.stop_event.is_set():
                 self.update_output("No open ports found in the specified range.")


    # --- Adapted SSID Listing Function ---
    # ... (list_ssids_windows_gui remains the same, updates GUI on error, returns list) ...
    def list_ssids_windows_gui(self):
        ssids = []
        try:
            command = ["netsh", "wlan", "show", "networks", "mode=Bssid"]
            creationflags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            result = subprocess.run(command, capture_output=True, text=True, shell=True, check=True, creationflags=creationflags)

            ssid_pattern = re.compile(r"^\s*SSID \d+\s*: (.*)$", re.MULTILINE)
            matches = ssid_pattern.findall(result.stdout)

            if matches:
                ssids = [ssid.strip() for ssid in matches]
                return ssids
            else:
                self.update_output("No SSIDs found in the netsh output.")
                return []

        except FileNotFoundError:
            self.update_output("Error: 'netsh' command not found. Make sure you are running this on Windows.")
            return None
        except subprocess.CalledProcessError as e:
            self.update_output(f"Error running netsh command: {e}")
            self.update_output(f"Stderr:\n {e.stderr}")
            return None
        except Exception as e:
            self.update_output(f"An unexpected error occurred during SSID scan: {e}")
            return None


    # --- Stop the current operation ---
    def stop_operation(self):
         self.stop_event.set()
         self.update_status("Attempting to stop operation...")


    # --- Handle window closing ---
    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.stop_operation()
            if self.current_thread and self.current_thread.is_alive():
                 self.current_thread.join(timeout=0.5)
            self.master.destroy()


# --- Main Application Setup ---
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()