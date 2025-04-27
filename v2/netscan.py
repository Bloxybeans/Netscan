# Required: pip install psutil requests python-whois
import subprocess
import socket
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, END, messagebox, ttk, BooleanVar, Menu, Toplevel, Label, Entry, Button, Frame
from tkinter import filedialog # For saving output
import re
import platform
import pyperclip
import queue
import ipaddress
import json             # For settings (optional future use) and parsing API responses
import http.client      # For HTTP Headers
import ssl              # For HTTPS context
from urllib.parse import urlparse # To help parse input for HTTP headers

# --- Attempt to import optional libraries ---
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# --- Configuration ---
SOCKET_TIMEOUT = 1.0
MAX_THREADS = 50
MAC_VENDOR_API_URL = "https://api.macvendors.com/" # Example API

# --- GUI Class ---
class NetworkScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Network Tool Suite") # Updated title
        master.geometry("750x650") # Expanded size

        self.style = ttk.Style()

        # --- Menu Bar ---
        self.menu_bar = Menu(master)
        master.config(menu=self.menu_bar)

        # File Menu (for Save/Exit) - Added
        self.file_menu = Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Save Main Output", command=self.save_main_output)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.on_closing)

        # Advanced Tools Menu
        self.tools_menu = Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Advanced Tools", menu=self.tools_menu)

        self.tools_menu.add_command(label="Traceroute", command=self.open_traceroute_window)
        self.tools_menu.add_command(label="DNS Lookup", command=self.open_dns_lookup_window)

        # Conditional Whois
        if WHOIS_AVAILABLE:
            self.tools_menu.add_command(label="Whois Lookup", command=self.open_whois_window)
        else:
            self.tools_menu.add_command(label="Whois Lookup (disabled - install python-whois)", state="disabled")

        self.tools_menu.add_separator()

        # Conditional Interface Info
        if PSUTIL_AVAILABLE:
             self.tools_menu.add_command(label="Network Interfaces", command=self.open_interfaces_window)
        else:
             self.tools_menu.add_command(label="Network Interfaces (disabled - install psutil)", state="disabled")

        self.tools_menu.add_command(label="ARP Cache", command=self.open_arp_cache_window)

        # Conditional MAC Lookup
        if REQUESTS_AVAILABLE:
             self.tools_menu.add_command(label="MAC Vendor Lookup", command=self.open_mac_lookup_window)
        else:
             self.tools_menu.add_command(label="MAC Vendor Lookup (disabled - install requests)", state="disabled")

        self.tools_menu.add_separator()
        self.tools_menu.add_command(label="HTTP Header Check", command=self.open_http_header_window)

        # Help Menu (Optional)
        self.help_menu = Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_about)


        # --- Main window layout ---
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(3, weight=1)

        # --- IP/Port Scanner Frame ---
        ip_port_frame = ttk.LabelFrame(master, text="IP & Port Scanner / Ping Tool", padding=(10, 10))
        ip_port_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ip_port_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(ip_port_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.entry_ip = ttk.Entry(ip_port_frame, width=40)
        self.entry_ip.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        self.entry_ip.insert(0, "127.0.0.1")

        ttk.Label(ip_port_frame, text="Ports (e.g., 80,443,1000-1024):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.entry_ports = ttk.Entry(ip_port_frame, width=40)
        self.entry_ports.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        self.entry_ports.insert(0, "1-100")

        self.skip_ping_var = BooleanVar(value=False)
        self.skip_ping_check = ttk.Checkbutton(ip_port_frame, text="Skip Host Reachability Check Before Scan", variable=self.skip_ping_var)
        self.skip_ping_check.grid(row=2, column=0, columnspan=3, padx=5, pady=2, sticky="w")

        self.scan_button = ttk.Button(ip_port_frame, text="Start Port Scan", command=self.start_ip_port_scan_thread)
        self.scan_button.grid(row=3, column=0, pady=10, padx=5, sticky="ew")
        self.ping_button = ttk.Button(ip_port_frame, text="Start Ping", command=self.start_ping_thread)
        self.ping_button.grid(row=3, column=1, pady=10, padx=5, sticky="ew")
        self.handshake_button = ttk.Button(ip_port_frame, text="Simulate Handshake", command=self.start_handshake_thread)
        self.handshake_button.grid(row=3, column=2, pady=10, padx=5, sticky="ew")

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(ip_port_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=4, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

        # --- SSID Lister Frame ---
        ssid_frame = ttk.LabelFrame(master, text="Wi-Fi SSID Lister", padding=(10, 10))
        ssid_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        ssid_frame.grid_columnconfigure(0, weight=1)
        self.ssid_scan_button = ttk.Button(ssid_frame, text="List SSIDs", command=self.start_ssid_scan_thread)
        self.ssid_scan_button.grid(row=0, column=0, pady=5, sticky="ew")
        if platform.system() != "Windows":
            self.ssid_scan_button.config(state='disabled', text="List SSIDs (Windows Only)")

        # --- Main Output Area ---
        self.main_output_label = ttk.Label(master, text="Main Tool Output:")
        self.main_output_label.grid(row=2, column=0, padx=10, pady=(10, 0), sticky="w")
        self.output_area = scrolledtext.ScrolledText(master, width=80, height=15, wrap=tk.WORD)
        self.output_area.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.output_area.bind("<Button-3>", self.show_context_menu)

        # --- Context Menu (for Copy) ---
        self.context_menu = tk.Menu(master, tearoff=0)
        self.context_menu.add_command(label="Copy Selected Text", command=self.copy_selected_text) # Command updated later

        # --- Status Bar ---
        self.status_label = ttk.Label(master, text="Ready.", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.grid(row=4, column=0, sticky="ew", padx=5, pady=2)

        # --- Stop Button ---
        self.stop_button = ttk.Button(master, text="Stop Current Operation", command=self.stop_operation)
        self.stop_button.grid(row=5, column=0, pady=(0, 10))

        # --- Threading/State Variables ---
        self.current_thread = None
        self.current_process = None
        self.stop_event = threading.Event()
        self.thread_semaphore = threading.Semaphore(MAX_THREADS)
        self.progress_queue = queue.Queue()
        self.active_tool_window = None
        # Warn about missing optional libraries once
        self._warned_libs = set()
        self._check_optional_libs()


    def _check_optional_libs(self):
        """ Check and potentially warn about missing libs in status bar """
        missing = []
        if not WHOIS_AVAILABLE: missing.append("python-whois (for Whois)")
        if not PSUTIL_AVAILABLE: missing.append("psutil (for Interfaces)")
        if not REQUESTS_AVAILABLE: missing.append("requests (for MAC Lookup)")
        if missing:
             self.update_status(f"Warning: Install {', '.join(missing)} for full functionality.")


    # --- Context Menu / Copy ---
    def show_context_menu(self, event):
        widget = event.widget
        if isinstance(widget, (tk.Text, scrolledtext.ScrolledText)):
             try:
                 has_selection = widget.tag_ranges(tk.SEL)
                 self.context_menu.entryconfig("Copy Selected Text",
                                               state="normal" if has_selection else "disabled",
                                               command=lambda w=widget: self.copy_selected_text(w))
                 self.context_menu.tk_popup(event.x_root, event.y_root)
             finally:
                 self.context_menu.grab_release()

    def copy_selected_text(self, text_widget=None):
        widget = text_widget or self.output_area
        # ... (copy logic remains the same) ...
        try:
            selected_text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            if selected_text:
                pyperclip.copy(selected_text)
                self.update_status("Selected text copied to clipboard.")
            else:
                 self.update_status("No text selected.")
        except tk.TclError:
            self.update_status("No text selected.")
        except Exception as e:
            self.update_main_output(f"Error copying text: {e}")


    # --- GUI Update Helpers ---
    # ... (update_main_output, update_output_widget, _perform_update_output, update_status, _perform_update_status, update_progress, _perform_update_progress remain the same) ...
    def update_main_output(self, message):
        self.master.after(0, self._perform_update_output, self.output_area, message)

    def update_output_widget(self, widget, message):
         self.master.after(0, self._perform_update_output, widget, message)

    def _perform_update_output(self, widget, message):
         if widget.winfo_exists(): # Check if widget still exists
             # Ensure widget is writable before inserting
             current_state = widget.cget("state")
             if current_state == 'disabled':
                  widget.config(state='normal')
                  widget.insert(END, message + "\n")
                  widget.config(state='disabled')
             else:
                  widget.insert(END, message + "\n")
             widget.see(END)


    def update_status(self, message):
         self.master.after(0, self._perform_update_status, message)

    def _perform_update_status(self, message):
         if self.status_label.winfo_exists():
             self.status_label.config(text=message)

    def update_progress(self, value):
        self.master.after(0, self._perform_update_progress, value)

    def _perform_update_progress(self, value):
        if self.progress_bar.winfo_exists():
            self.progress_var.set(value)


    # --- Button/Menu State Management ---
    def set_button_state(self, state):
         """ Sets the state ('normal' or 'disabled') for operational buttons/menus. """
         # Determine actual desired state ('normal' or 'disabled')
         effective_state = state if state in ['normal', 'disabled'] else 'disabled'

         # Main operational buttons
         main_buttons = [self.scan_button, self.ping_button, self.handshake_button, self.stop_button]
         if platform.system() == "Windows":
             main_buttons.append(self.ssid_scan_button)

         for button in main_buttons:
              if button and button.winfo_exists():
                  button.config(state=effective_state)

         # File Menu Items (only Save needs disabling)
         if hasattr(self, 'file_menu') and self.file_menu.winfo_exists():
              try:
                 self.file_menu.entryconfig("Save Main Output", state=effective_state)
              except tk.TclError: pass # Ignore if item doesn't exist

         # Advanced Tools Menu Items
         if hasattr(self, 'tools_menu') and self.tools_menu.winfo_exists():
              # List of tuples: (label, is_available_flag or True)
              tool_items = [
                  ("Traceroute", True),
                  ("DNS Lookup", True),
                  ("Whois Lookup", WHOIS_AVAILABLE),
                  ("Network Interfaces", PSUTIL_AVAILABLE),
                  ("ARP Cache", True),
                  ("MAC Vendor Lookup", REQUESTS_AVAILABLE),
                  ("HTTP Header Check", True),
              ]
              for label, available in tool_items:
                   actual_label = label
                   # Adjust label for unavailable items
                   if not available:
                        if label == "Whois Lookup": actual_label = "Whois Lookup (disabled - install python-whois)"
                        elif label == "Network Interfaces": actual_label = "Network Interfaces (disabled - install psutil)"
                        elif label == "MAC Vendor Lookup": actual_label = "MAC Vendor Lookup (disabled - install requests)"

                   try:
                       final_state = effective_state if available else 'disabled'
                       self.tools_menu.entryconfig(actual_label, state=final_state)
                   except tk.TclError: pass # Ignore if menu item doesn't exist


    # --- Input Parsing (Ports) ---
    def parse_ports(self, port_string):
        # ... (remains the same) ...
        ports = set()
        if not port_string:
            return []
        parts = port_string.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if 0 <= start <= end <= 65535:
                        ports.update(range(start, end + 1))
                    else:
                        raise ValueError("Port range values out of bounds (0-65535).")
                except ValueError:
                     raise ValueError(f"Invalid port range format: '{part}'. Use start-end.")
            else:
                try:
                    port_num = int(part)
                    if 0 <= port_num <= 65535:
                        ports.add(port_num)
                    else:
                        raise ValueError("Port number out of bounds (0-65535).")
                except ValueError:
                    raise ValueError(f"Invalid port number: '{part}'.")
        return sorted(list(ports))


    # --- Thread/Process Starters ---
    def start_operation(self, target_func, op_type="thread", *args):
        # ... (logic remains similar, ensure cleanup resets state) ...
        if self.current_thread and self.current_thread.is_alive():
            self.update_status("Another operation already in progress...")
            return False
        if self.current_process and self.current_process.poll() is None:
             self.update_status("Another operation (process) already in progress...")
             return False

        self.set_button_state('disabled') # Disable buttons and menu items
        self.stop_event.clear()
        self.update_progress(0)
        self.current_process = None # Ensure process handle is cleared

        # Create the thread that will run the target function (which might manage a process)
        self.current_thread = threading.Thread(target=target_func, args=args, daemon=True)
        self.current_thread.start()
        return True


    # --- Main Tool Starters ---
    # ... (start_ip_port_scan_thread, start_ping_thread, start_handshake_thread, start_ssid_scan_thread remain mostly the same, clear main output before starting) ...
    def start_ip_port_scan_thread(self):
        target_ip = self.entry_ip.get()
        port_range_str = self.entry_ports.get()
        if not target_ip:
             messagebox.showwarning("Input Error", "Please enter a target IP address.", parent=self.master)
             return
        try:
            ports_to_scan = self.parse_ports(port_range_str)
            if not ports_to_scan:
                messagebox.showwarning("Input Error", "Please enter valid ports or port ranges.", parent=self.master)
                return
        except ValueError as e:
            messagebox.showwarning("Input Error", f"Invalid port input: {e}", parent=self.master)
            return
        self.output_area.delete('1.0', END)
        if self.start_operation(self.run_ip_port_scan, "scan", target_ip, ports_to_scan, self.skip_ping_var.get()):
            self.update_status(f"Starting Port scan on {target_ip} for {len(ports_to_scan)} ports...")
            self.master.after(100, self.check_progress_queue)


    def start_ping_thread(self):
        target_ip = self.entry_ip.get()
        if not target_ip:
             messagebox.showwarning("Input Error", "Please enter a target IP address to ping.", parent=self.master)
             return
        self.output_area.delete('1.0', END)
        if self.start_operation(self.run_ping_tool, "process", target_ip):
             self.update_status(f"Starting ping to {target_ip}...")

    def start_handshake_thread(self):
         target_ip = self.entry_ip.get()
         port_str = self.entry_ports.get().split(',')[0].split('-')[0].strip()
         if not target_ip:
              messagebox.showwarning("Input Error", "Please enter target IP.", parent=self.master)
              return
         if not port_str:
             messagebox.showwarning("Input Error", "Please enter at least one port for the handshake.", parent=self.master)
             return
         try:
             target_port = int(port_str)
             if not (0 <= target_port <= 65535): raise ValueError("Invalid port value.")
         except ValueError:
             messagebox.showwarning("Input Error", f"Invalid port value: '{port_str}'.", parent=self.master)
             return
         self.output_area.delete('1.0', END)
         if self.start_operation(self.run_handshake_simulator, "handshake", target_ip, target_port):
             self.update_status(f"Simulating TCP handshake with {target_ip}:{target_port}...")

    def start_ssid_scan_thread(self):
         if platform.system() != "Windows":
              messagebox.showerror("OS Error", "SSID listing is only supported on Windows.", parent=self.master)
              return
         self.output_area.delete('1.0', END)
         if self.start_operation(self.run_ssid_scan, "ssid"):
              self.update_status("Starting SSID scan...")


    # --- Advanced Tool Window Generation ---
    def open_advanced_tool_window(self, tool_name, run_command, takes_target=True, needs_run_button=True):
        """ Creates a generic Toplevel window for an advanced tool. """
        # Prevent opening multiple tool windows or running while main op active
        if self.active_tool_window and self.active_tool_window.winfo_exists():
            messagebox.showwarning("Window Busy", "Another advanced tool window is already open.", parent=self.master)
            self.active_tool_window.lift() # Bring existing window to front
            self.active_tool_window.focus()
            return None # Indicate failure
        if self.current_thread and self.current_thread.is_alive() or \
           self.current_process and self.current_process.poll() is None:
             messagebox.showwarning("Operation Running", "Please wait for the current main operation to finish or stop it.", parent=self.master)
             return None # Indicate failure

        # --- Create Window ---
        tool_window = Toplevel(self.master)
        tool_window.title(tool_name)
        tool_window.geometry("600x450") # Adjusted size
        self.active_tool_window = tool_window
        tool_window.transient(self.master)
        tool_window.grab_set() # Make modal

        # --- Widgets ---
        tool_window.grid_columnconfigure(0, weight=1)
        tool_window.grid_rowconfigure(1 if takes_target else 0, weight=1) # Output row expands

        target_entry = None
        run_button = None
        # Optional Input Frame
        if takes_target:
            input_frame = ttk.Frame(tool_window, padding=(5, 5))
            input_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
            input_frame.grid_columnconfigure(1, weight=1)
            ttk.Label(input_frame, text="Target:").grid(row=0, column=0, padx=5, sticky="w")
            target_entry = ttk.Entry(input_frame, width=40)
            target_entry.grid(row=0, column=1, padx=5, sticky="ew")
            # Pre-fill if relevant (e.g., IP for traceroute, domain for whois)
            # Smart prefill could be added later based on tool_name
            target_entry.insert(0, self.entry_ip.get())

            if needs_run_button:
                run_button = ttk.Button(input_frame, text=f"Run {tool_name}", width=15)
                run_button.grid(row=0, column=2, padx=5)

        # Output Area (always present)
        output_widget = scrolledtext.ScrolledText(tool_window, width=70, height=20, wrap=tk.WORD)
        output_widget.grid(row=1 if takes_target else 0, column=0, padx=5, pady=(0,5), sticky="nsew")
        output_widget.bind("<Button-3>", self.show_context_menu)
        # Make output read-only initially if needed, enable before writing
        # output_widget.config(state='disabled')

        # Bottom Frame for Buttons
        button_frame = ttk.Frame(tool_window, padding=(5,5))
        button_frame.grid(row=2 if takes_target else 1, column=0, sticky="ew")
        button_frame.grid_columnconfigure(0, weight=1) # Center buttons (optional)
        button_frame.grid_columnconfigure(1, weight=1)

        # Add Save Output Button
        save_button = ttk.Button(button_frame, text="Save Output",
                                 command=lambda w=output_widget: self.save_widget_output(w))
        save_button.grid(row=0, column=0, padx=5, pady=5)

        # Add Close button
        close_button = ttk.Button(button_frame, text="Close",
                                  command=lambda: self.close_tool_window(tool_window))
        close_button.grid(row=0, column=1, padx=5, pady=5)


        # Configure the run button's command (if it exists)
        if run_button:
             run_button.config(command=lambda: run_command(target_entry.get(), output_widget, run_button, close_button, save_button))
        # Handle window close button ([X])
        tool_window.protocol("WM_DELETE_WINDOW", lambda: self.close_tool_window(tool_window))

        # If no run button needed (e.g., interfaces, ARP cache), run command immediately
        if not needs_run_button:
            # Ensure run_command expects these args even if button not used
             run_command(None, output_widget, None, close_button, save_button)

        return tool_window # Return handle if needed

    def close_tool_window(self, window):
        # ... (logic remains the same) ...
        if window and window.winfo_exists():
             if self.current_thread and self.current_thread.is_alive() or \
                self.current_process and self.current_process.poll() is None:
                 if messagebox.askyesno("Operation Running", "An operation is running. Stop it and close?", parent=window):
                     self.stop_operation()
                     self.master.after(50, lambda w=window: self._destroy_window_if_exists(w))
                 else:
                     return False # User cancelled close
             else:
                 self._destroy_window_if_exists(window)
        return True # Indicate closed or didn't need closing

    def _destroy_window_if_exists(self, window):
         if window and window.winfo_exists():
             window.grab_release() # Release grab before destroying
             window.destroy()
         if self.active_tool_window == window:
             self.active_tool_window = None


    # --- Advanced Tool Window Openers ---
    def open_traceroute_window(self):
        self.open_advanced_tool_window("Traceroute", self.start_traceroute)

    def open_dns_lookup_window(self):
        self.open_advanced_tool_window("DNS Lookup", self.start_dns_lookup)

    def open_whois_window(self):
        if not self._check_lib_available(WHOIS_AVAILABLE, "python-whois"): return
        self.open_advanced_tool_window("Whois Lookup", self.start_whois_lookup)

    def open_interfaces_window(self):
        if not self._check_lib_available(PSUTIL_AVAILABLE, "psutil"): return
        # Doesn't need target input or a run button, runs immediately
        self.open_advanced_tool_window("Network Interfaces", self.start_interface_info, takes_target=False, needs_run_button=False)

    def open_arp_cache_window(self):
         # Doesn't need target input or a run button, runs immediately
         self.open_advanced_tool_window("ARP Cache", self.start_arp_display, takes_target=False, needs_run_button=False)

    def open_mac_lookup_window(self):
        if not self._check_lib_available(REQUESTS_AVAILABLE, "requests"): return
        # Needs target input (MAC address)
        tool_window = self.open_advanced_tool_window("MAC Vendor Lookup", self.start_mac_lookup)
        if tool_window:
            # Find the target entry widget in the new window to modify label/prefill
             for child in tool_window.winfo_children():
                 if isinstance(child, ttk.Frame): # Find input frame
                     for grandchild in child.winfo_children():
                          if isinstance(grandchild, ttk.Label) and "Target" in grandchild.cget("text"):
                              grandchild.config(text="MAC Address:")
                          if isinstance(grandchild, ttk.Entry):
                              grandchild.delete(0, END) # Clear IP prefill
                              grandchild.insert(0, "00:11:22:AA:BB:CC") # Example MAC

    def open_http_header_window(self):
         # Needs target input (URL or host:port)
         tool_window = self.open_advanced_tool_window("HTTP Header Check", self.start_http_headers)
         if tool_window:
            # Find the target entry widget to modify label/prefill
             for child in tool_window.winfo_children():
                 if isinstance(child, ttk.Frame): # Find input frame
                     for grandchild in child.winfo_children():
                          if isinstance(grandchild, ttk.Label) and "Target" in grandchild.cget("text"):
                              grandchild.config(text="URL or Host[:Port]:")
                          if isinstance(grandchild, ttk.Entry):
                              grandchild.delete(0, END) # Clear IP prefill
                              grandchild.insert(0, "https://www.google.com") # Example


    # --- Helper to check optional library availability ---
    def _check_lib_available(self, available_flag, lib_name):
        if not available_flag:
            if lib_name not in self._warned_libs: # Show messagebox only once per session
                messagebox.showerror("Library Missing",
                                     f"The '{lib_name}' library is required for this tool.\nPlease install it (e.g., pip install {lib_name}) and restart.",
                                     parent=self.active_tool_window or self.master)
                self._warned_libs.add(lib_name)
            return False
        return True

    # --- Saving Output ---
    def save_widget_output(self, output_widget):
        """Saves the content of a ScrolledText widget to a file."""
        content = output_widget.get('1.0', END).strip()
        if not content:
            messagebox.showwarning("No Output", "There is no output to save.",
                                   parent=self.active_tool_window or self.master)
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("Log Files", "*.log"), ("All Files", "*.*")],
            title="Save Output As...",
            parent=self.active_tool_window or self.master
        )
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.update_status(f"Output saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save output:\n{e}",
                                     parent=self.active_tool_window or self.master)

    def save_main_output(self):
        """Specifically saves the main output area."""
        self.save_widget_output(self.output_area)


    # --- Advanced Tool Starters & Runners ---

    # ... (start_traceroute, run_traceroute, start_dns_lookup, run_dns_lookup, start_whois_lookup, run_whois_lookup remain the same, just ensure buttons passed can be None) ...
    # Example adaptation for run_traceroute
    def run_traceroute(self, target, output_widget, run_button, close_button, save_button): # Added save_button
        # ... (command setup) ...
        is_windows = platform.system() == "Windows"
        command = ["tracert" if is_windows else "traceroute", target]
        self.update_output_widget(output_widget, f"Running command: {' '.join(command)}\n" + "-"*20)

        try:
             # ... (subprocess execution and output streaming) ...
            startupinfo = None; creationflags = 0
            if is_windows: creationflags = subprocess.CREATE_NO_WINDOW
            self.current_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                   text=True, universal_newlines=True,
                                                   creationflags=creationflags, startupinfo=startupinfo)
            for line in iter(self.current_process.stdout.readline, ''):
                if self.stop_event.is_set():
                    self.update_output_widget(output_widget, "\n[!] Traceroute stopped by user.")
                    break
                if line: self.update_output_widget(output_widget, line.strip())
                time.sleep(0.01)
            self.current_process.stdout.close()
            return_code = self.current_process.wait()
            if not self.stop_event.is_set():
                self.update_output_widget(output_widget, "-"*20 + f"\nTraceroute finished with code {return_code}.")

        except FileNotFoundError: self.update_output_widget(output_widget, f"[!] Error: '{command[0]}' not found.")
        except Exception as e: self.update_output_widget(output_widget, f"[!] Error: {e}")
        finally:
             if self.stop_event.is_set() and self.current_process and self.current_process.poll() is None:
                 try: self.current_process.terminate(); self.current_process.wait(timeout=1)
                 except Exception: pass
             # --- Cleanup ---
             self.update_status("Traceroute finished.")
             self.current_process = None; self.current_thread = None
             # Re-enable buttons via main thread if they exist
             def _reenable():
                 self.set_button_state('normal') # Re-enable main buttons/menus
                 if run_button and run_button.winfo_exists(): run_button.config(state="normal")
                 if close_button and close_button.winfo_exists(): close_button.config(state="normal")
                 if save_button and save_button.winfo_exists(): save_button.config(state="normal")
             self.master.after(0, _reenable)


    # --- Network Interface Info ---
    def start_interface_info(self, target, output_widget, run_button, close_button, save_button):
         # Runs immediately, no separate thread needed as psutil is fast
         # Disable close/save buttons while running
         if close_button: close_button.config(state='disabled')
         if save_button: save_button.config(state='disabled')
         output_widget.delete('1.0', END)
         self.update_status("Getting Network Interface Information...")
         self.run_interface_info(output_widget)
         self.update_status("Interface Information Ready.")
         if close_button: close_button.config(state='normal')
         if save_button: save_button.config(state='normal')
         # No current_thread or current_process to clear

    def run_interface_info(self, output_widget):
        if not self._check_lib_available(PSUTIL_AVAILABLE, "psutil"):
             self.update_output_widget(output_widget, "psutil library is required but not installed.")
             return
        self.update_output_widget(output_widget, "Network Interfaces:\n" + "="*20)
        try:
            all_stats = psutil.net_if_stats()
            all_addrs = psutil.net_if_addrs()

            for name, addrs in all_addrs.items():
                self.update_output_widget(output_widget, f"Interface: {name}")
                # Get Status (UP/DOWN)
                status = "UNKNOWN"
                if name in all_stats:
                     status = "UP" if all_stats[name].isup else "DOWN"
                self.update_output_widget(output_widget, f"  Status: {status}")

                # Get Addresses
                for addr in addrs:
                    family = ""
                    if addr.family == socket.AF_INET:
                        family = "IPv4"
                    elif addr.family == socket.AF_INET6:
                        family = "IPv6"
                    elif psutil.LINUX and addr.family == psutil.AF_LINK: # Linux specific for MAC
                         family = "MAC"
                    elif hasattr(socket, 'AF_PACKET') and addr.family == socket.AF_PACKET: # Generic check for MAC
                         family = "MAC"

                    if family == "MAC":
                         self.update_output_widget(output_widget, f"  {family:<4}: {addr.address}")
                    elif family: # IPv4 or IPv6
                         self.update_output_widget(output_widget, f"  {family:<4}: {addr.address}")
                         if addr.netmask:
                             self.update_output_widget(output_widget, f"         Netmask: {addr.netmask}")
                         # Broadcast is often None or irrelevant for IPv6
                         # if addr.broadcast:
                         #     self.update_output_widget(output_widget, f"         Broadcast: {addr.broadcast}")
                self.update_output_widget(output_widget, "-"*20)

        except Exception as e:
             self.update_output_widget(output_widget, f"\n[!] Error retrieving interface info: {e}")
        self.update_output_widget(output_widget, "Interface listing finished.")


    # --- ARP Cache Display ---
    def start_arp_display(self, target, output_widget, run_button, close_button, save_button):
        # Disable buttons while running
        if close_button: close_button.config(state='disabled')
        if save_button: save_button.config(state='disabled')
        output_widget.delete('1.0', END)
        self.update_status("Getting ARP Cache...")
        # ARP command is fast, but use thread for consistency with subprocess pattern
        if not self.start_operation(self.run_arp_display, "process", output_widget, close_button, save_button):
            # Re-enable if start failed
            if close_button: close_button.config(state='normal')
            if save_button: save_button.config(state='normal')

    def run_arp_display(self, output_widget, close_button, save_button):
        command = ["arp", "-a"]
        self.update_output_widget(output_widget, f"Running command: {' '.join(command)}\n" + "="*20)
        try:
            startupinfo = None; creationflags = 0
            if platform.system() == "Windows": creationflags = subprocess.CREATE_NO_WINDOW
            self.current_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                   text=True, universal_newlines=True,
                                                   creationflags=creationflags, startupinfo=startupinfo)

            output, _ = self.current_process.communicate(timeout=5) # 5 second timeout

            if self.stop_event.is_set(): # Should be very quick, but check anyway
                 self.update_output_widget(output_widget, "\n[!] ARP display stopped.")
                 return

            if self.current_process.returncode == 0:
                 self.update_output_widget(output_widget, output.strip())
                 self.update_output_widget(output_widget, "\n" + "="*20 + "\nARP Cache display finished.")
            else:
                 self.update_output_widget(output_widget, f"[!] Command failed with code {self.current_process.returncode}:\n{output}")

        except FileNotFoundError:
            self.update_output_widget(output_widget, f"[!] Error: '{command[0]}' command not found.")
        except subprocess.TimeoutExpired:
             self.update_output_widget(output_widget, "[!] Error: 'arp -a' command timed out.")
        except Exception as e:
            self.update_output_widget(output_widget, f"[!] An unexpected error occurred: {e}")
        finally:
             # --- Cleanup ---
             self.update_status("ARP Cache Ready.")
             self.current_process = None; self.current_thread = None
             def _reenable():
                 self.set_button_state('normal') # Re-enable main buttons/menus
                 if close_button and close_button.winfo_exists(): close_button.config(state="normal")
                 if save_button and save_button.winfo_exists(): save_button.config(state="normal")
             self.master.after(0, _reenable)


    # --- MAC Vendor Lookup ---
    def start_mac_lookup(self, mac_address, output_widget, run_button, close_button, save_button):
        if not self._check_lib_available(REQUESTS_AVAILABLE, "requests"): return
        mac_address = mac_address.strip()
        # Basic MAC validation (simple regex)
        if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac_address):
             messagebox.showwarning("Input Error", "Invalid MAC address format.\nUse XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX", parent=self.active_tool_window)
             return
        if run_button: run_button.config(state='disabled')
        if close_button: close_button.config(state='disabled')
        if save_button: save_button.config(state='disabled')
        output_widget.delete('1.0', END)
        self.update_status(f"Looking up MAC Vendor for {mac_address}...")
        # Network lookup, run in thread
        if not self.start_operation(self.run_mac_lookup, "thread", mac_address, output_widget, run_button, close_button, save_button):
             # Re-enable if start failed
             if run_button: run_button.config(state='normal')
             if close_button: close_button.config(state='normal')
             if save_button: save_button.config(state='normal')

    def run_mac_lookup(self, mac_address, output_widget, run_button, close_button, save_button):
        api_endpoint = f"{MAC_VENDOR_API_URL}{mac_address}"
        self.update_output_widget(output_widget, f"Querying: {api_endpoint}\n" + "="*20)
        headers = {'Accept': 'application/json'} # Prefer JSON response if available
        try:
            if self.stop_event.is_set(): return # Check before network call

            response = requests.get(api_endpoint, headers=headers, timeout=10) # 10 sec timeout

            if self.stop_event.is_set(): return # Check after network call

            if response.status_code == 200:
                 try:
                     # Try parsing as JSON first (some APIs might return JSON)
                     data = response.json()
                     if isinstance(data, dict) and 'company' in data:
                          self.update_output_widget(output_widget, f"MAC Address: {mac_address}")
                          self.update_output_widget(output_widget, f"Vendor: {data['company']}")
                          # Add other fields if available, e.g., address, country
                     else: # Assume plain text vendor name if JSON parse fails or lacks expected keys
                          self.update_output_widget(output_widget, f"MAC Address: {mac_address}")
                          self.update_output_widget(output_widget, f"Vendor: {response.text.strip()}")
                 except json.JSONDecodeError:
                     # If not JSON, assume plain text response
                     self.update_output_widget(output_widget, f"MAC Address: {mac_address}")
                     self.update_output_widget(output_widget, f"Vendor: {response.text.strip()}")

            elif response.status_code == 404:
                 self.update_output_widget(output_widget, f"Vendor not found for MAC: {mac_address}")
            else:
                 self.update_output_widget(output_widget, f"[!] Error: Received HTTP status {response.status_code}")
                 self.update_output_widget(output_widget, f"Response: {response.text[:200]}...") # Show partial response

        except requests.exceptions.Timeout:
            self.update_output_widget(output_widget, "[!] Error: Request timed out.")
        except requests.exceptions.RequestException as e:
             self.update_output_widget(output_widget, f"[!] Error during MAC lookup request: {e}")
        except Exception as e:
            self.update_output_widget(output_widget, f"[!] An unexpected error occurred: {e}")
        finally:
             # --- Cleanup ---
             status_msg = "MAC Lookup Stopped." if self.stop_event.is_set() else "MAC Lookup Finished."
             self.update_status(status_msg)
             self.current_thread = None
             def _reenable():
                 self.set_button_state('normal') # Re-enable main buttons/menus
                 if run_button and run_button.winfo_exists(): run_button.config(state="normal")
                 if close_button and close_button.winfo_exists(): close_button.config(state="normal")
                 if save_button and save_button.winfo_exists(): save_button.config(state="normal")
             self.master.after(0, _reenable)


    # --- HTTP Header Check ---
    def start_http_headers(self, target_url, output_widget, run_button, close_button, save_button):
        target_url = target_url.strip()
        if not target_url:
             messagebox.showwarning("Input Error", "Please enter a URL (e.g., http://example.com) or Host[:Port]", parent=self.active_tool_window)
             return

        if run_button: run_button.config(state='disabled')
        if close_button: close_button.config(state='disabled')
        if save_button: save_button.config(state='disabled')
        output_widget.delete('1.0', END)
        self.update_status(f"Checking HTTP Headers for {target_url}...")
        # Network lookup, run in thread
        if not self.start_operation(self.run_http_headers, "thread", target_url, output_widget, run_button, close_button, save_button):
             if run_button: run_button.config(state='normal')
             if close_button: close_button.config(state='normal')
             if save_button: save_button.config(state='normal')


    def run_http_headers(self, target_url, output_widget, run_button, close_button, save_button):
        self.update_output_widget(output_widget, f"Fetching headers for: {target_url}\n" + "="*20)
        conn = None
        try:
            # Prepend scheme if missing for urlparse
            if not target_url.startswith(('http://', 'https://')):
                 # Default to http, but allow specifying port for non-standard http/https
                 if ':' in target_url.split('/')[-1]: # Check if port likely specified in host part
                     target_url = "http://" + target_url
                 else: # Try https first if no scheme/port specified? Or stick to http? Let's try https default.
                      # This logic could be improved. Maybe try https, then http on failure?
                      try:
                          # Quick check if port 443 is open before assuming https
                          host_only = target_url.split('/')[0]
                          temp_sock = socket.create_connection((host_only, 443), timeout=1)
                          temp_sock.close()
                          target_url = "https://" + target_url
                      except Exception:
                           target_url = "http://" + target_url


            parsed_url = urlparse(target_url)
            host = parsed_url.netloc
            path = parsed_url.path if parsed_url.path else "/"
            if parsed_url.query: path += "?" + parsed_url.query # Include query string

            port = None
            if ':' in host: # Check if port specified in netloc
                 host, port_str = host.split(':', 1)
                 try: port = int(port_str)
                 except ValueError: raise ValueError("Invalid port in URL")

            if self.stop_event.is_set(): return

            if parsed_url.scheme == "https":
                port = port or 443
                # Create SSL context (basic validation)
                context = ssl.create_default_context()
                # You might want to disable hostname checking for self-signed certs, but it's insecure:
                # context.check_hostname = False
                # context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=10, context=context)
            elif parsed_url.scheme == "http":
                port = port or 80
                conn = http.client.HTTPConnection(host, port, timeout=10)
            else:
                raise ValueError(f"Unsupported URL scheme: {parsed_url.scheme}")

            self.update_output_widget(output_widget, f"Connecting to {host}:{port}...")
            conn.request("HEAD", path) # Use HEAD request to just get headers
            response = conn.getresponse()

            if self.stop_event.is_set():
                 if conn: conn.close()
                 return

            self.update_output_widget(output_widget, f"\nStatus: {response.status} {response.reason}")
            self.update_output_widget(output_widget, "\nHeaders:\n" + "-"*15)
            for header, value in response.getheaders():
                 self.update_output_widget(output_widget, f"{header}: {value}")

            # Follow redirects (limited depth)? HEAD doesn't usually redirect automatically.
            # Could add logic here to check for 3xx status and Location header, then make a new request.

        except (http.client.HTTPException, socket.gaierror, ConnectionRefusedError, socket.timeout, OSError) as e:
             self.update_output_widget(output_widget, f"\n[!] Error connecting or retrieving headers: {e}")
        except ssl.SSLCertVerificationError as e:
             self.update_output_widget(output_widget, f"\n[!] SSL Certificate Verification Error: {e.reason} (Target might use self-signed/invalid cert)")
        except ValueError as e: # Handle invalid URL/port
             self.update_output_widget(output_widget, f"\n[!] Input Error: {e}")
        except Exception as e:
             self.update_output_widget(output_widget, f"\n[!] An unexpected error occurred: {e}")
        finally:
            if conn:
                conn.close()
             # --- Cleanup ---
            status_msg = "HTTP Header Check Stopped." if self.stop_event.is_set() else "HTTP Header Check Finished."
            self.update_status(status_msg)
            self.current_thread = None
            def _reenable():
                 self.set_button_state('normal') # Re-enable main buttons/menus
                 if run_button and run_button.winfo_exists(): run_button.config(state="normal")
                 if close_button and close_button.winfo_exists(): close_button.config(state="normal")
                 if save_button and save_button.winfo_exists(): save_button.config(state="normal")
            self.master.after(0, _reenable)


    # --- Main logic runners (run_ip_port_scan, run_ping_tool, run_handshake_simulator, run_ssid_scan) ---
    # ... Need to ensure they call the _reenable logic in their finally blocks ...
    # Example for run_ip_port_scan cleanup:
    def run_ip_port_scan(self, target_ip, ports_to_scan, skip_ping):
        # ... (existing reachability and scan logic) ...
        scan_completed = False
        try:
            # ... (ping check logic) ...
            if reachable and not self.stop_event.is_set():
                scan_completed = self.threaded_port_scan_gui(target_ip, ports_to_scan)
        finally:
             # --- Final Status Update & Cleanup ---
             final_status = "IP/Port Scan Finished."
             if self.stop_event.is_set(): final_status = "IP/Port Scan Stopped by user."
             elif not reachable and not skip_ping: final_status = "IP/Port Scan Aborted (Host unreachable)."
             self.update_status(final_status)
             self.progress_queue.put(100.0 if scan_completed and not self.stop_event.is_set() else 0.0)
             self.current_thread = None
             self.master.after(0, lambda: self.set_button_state('normal')) # Re-enable


    # --- Core Scanning Functions ---
    # ... (scan_port_gui, threaded_port_scan_gui, list_ssids_windows_gui remain the same) ...
    def scan_port_gui(self, target_ip, port, open_ports_list, total_ports, scanned_count):
        # ... (remains the same) ...
        with self.thread_semaphore:
            if self.stop_event.is_set(): return
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(SOCKET_TIMEOUT)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    banner = ""
                    try:
                        s.settimeout(0.5); banner_bytes = s.recv(1024); banner = banner_bytes.decode('utf-8', errors='replace').strip()
                    except (socket.timeout, ConnectionResetError): pass
                    except Exception: pass
                    output_line = f"[+] Port {port} is open"
                    if banner: output_line += f" (Banner: {banner[:60]}{'...' if len(banner) > 60 else ''})"
                    self.update_main_output(output_line)
                    open_ports_list.append(port)
                s.close()
            except socket.gaierror: pass
            except socket.error: pass
            except Exception as e: self.update_main_output(f"[!] Unexpected error scanning port {port}: {e}")
            finally:
                 with scanned_count_lock:
                    scanned_count[0] += 1
                    progress = (scanned_count[0] / total_ports) * 100
                    self.progress_queue.put(progress)

    # --- Progress Queue Checker ---
    # ... (remains the same) ...
    def check_progress_queue(self):
        try:
            while not self.progress_queue.empty():
                progress = self.progress_queue.get_nowait()
                self.update_progress(progress)
            # Check if the specific thread managing the scan is active
            if self.current_thread and self.current_thread.is_alive() and getattr(self.current_thread, '_target', None) == self.run_ip_port_scan:
                self.master.after(100, self.check_progress_queue)
        except queue.Empty:
             if self.current_thread and self.current_thread.is_alive() and getattr(self.current_thread, '_target', None) == self.run_ip_port_scan:
                self.master.after(100, self.check_progress_queue)

    # --- Stop Operation ---
    # ... (remains the same) ...
    def stop_operation(self):
        stopped_something = False
        if self.current_thread and self.current_thread.is_alive():
            self.update_status("Attempting to stop current operation...")
            self.stop_event.set()
            stopped_something = True
        elif self.current_process and self.current_process.poll() is None:
             self.update_status("Attempting to stop current process...")
             self.stop_event.set()
             try: self.current_process.terminate(); stopped_something = True
             except Exception as e: self.update_status(f"Could not terminate process: {e}")
        if not stopped_something: self.update_status("No operation detected running.")
        else: self.stop_button.config(state="disabled")


    # --- About Box ---
    def show_about(self):
        about_text = """Advanced Network Tool Suite
Version: 1.2 (Expanded Features)

Includes tools for:
- Port Scanning (TCP Connect)
- Ping
- TCP Handshake Simulation
- Wi-Fi SSID Listing (Windows)
- Traceroute (System command)
- DNS Lookup (socket)
- Whois Lookup (requires 'python-whois')
- Network Interface Info (requires 'psutil')
- ARP Cache Display (System command)
- MAC Vendor Lookup (requires 'requests')
- HTTP Header Check (http.client)

Note: Some features require external libraries to be installed.
Advanced scanning (SYN, UDP, Service/OS Detection) typically requires Nmap and admin privileges, which are not integrated here.
"""
        messagebox.showinfo("About", about_text, parent=self.master)


    # --- Handle Window Closing ---
    # ... (remains the same) ...
    def on_closing(self):
        if self.active_tool_window and self.active_tool_window.winfo_exists():
             if not self.close_tool_window(self.active_tool_window): return
        if self.current_thread and self.current_thread.is_alive() or \
           self.current_process and self.current_process.poll() is None:
            if messagebox.askokcancel("Quit", "An operation might still be running. Quit anyway?", parent=self.master):
                self.stop_operation(); self.master.after(50, self.master.destroy)
            else: return
        else:
             if messagebox.askokcancel("Quit", "Do you want to quit?", parent=self.master):
                  self.master.destroy()


# --- Main Application Setup ---
if __name__ == "__main__":
    root = tk.Tk()
    # Add application icon (optional, replace 'icon.ico'/'icon.png')
    # try:
    #    if platform.system() == "Windows":
    #        root.iconbitmap('icon.ico')
    #    else:
    #        # For Linux/macOS, PhotoImage supports PNG, GIF
    #        img = tk.PhotoImage(file='icon.png')
    #        root.tk.call('wm', 'iconphoto', root._w, img)
    # except Exception as e:
    #    print(f"Icon loading error: {e}")

    app = NetworkScannerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()