import re
import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import threading
import psutil
import socket
import ipaddress
from plyer import notification

class NetworkDiscoveryPage(tk.Frame):
    def __init__(self, parent, notebook):
        super().__init__(parent)
        self.notebook = notebook  # Store reference to the notebook for enabling/disabling tabs
        self.configure(bg='#DFD3C3')  # Set the background of the frame
        self.setup_ui()

    def setup_ui(self):
        # Define the new color palette and font style
        bg_color = "#F8EDE3"
        frame_color = "#DFD3C3"
        button_color = "#D0B8A8"
        text_color = "#C5705D"
        word_style = "Calibri"  # Define the font style to be used

        # Layout frames with the new color palette
        frame_header = tk.Frame(self, bg=frame_color, pady=10)
        frame_header.pack()

        frame_discovery_input = tk.Frame(self, bg=frame_color, padx=20, pady=10)
        frame_discovery_input.pack()

        frame_discovery_output = tk.Frame(self, bg=frame_color, padx=20, pady=10)
        frame_discovery_output.pack()

        frame_buttons = tk.Frame(self, bg=frame_color, padx=20, pady=10)
        frame_buttons.pack()  # Place this below the output

        frame_progress = tk.Frame(self, bg=frame_color, pady=20)
        frame_progress.pack()

        frame_status = tk.Frame(self, bg=frame_color, padx=20, pady=10)
        frame_status.pack(side=tk.BOTTOM, fill=tk.X)


        # Network discovery input
        tk.Label(frame_discovery_input, text="Network Range (e.g., 192.168.1.0/24):", font=(word_style, 12),
                 bg=frame_color, fg=text_color).grid(row=0, column=0, padx=10, pady=5)
        self.discovery_ip_entry = tk.Entry(frame_discovery_input, font=(word_style, 14), width=30,
                                           bg=bg_color, fg=text_color)
        self.discovery_ip_entry.grid(row=0, column=1, padx=10, pady=5)

        # Discovery results text box with scrollbar
        scrollbar = tk.Scrollbar(frame_discovery_output)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.discovery_results_text = tk.Text(frame_discovery_output, wrap=tk.WORD, yscrollcommand=scrollbar.set,
                                              font=(word_style, 12), height=15, width=70, bg=bg_color, fg=text_color)
        self.discovery_results_text.pack(padx=10, pady=10)
        scrollbar.config(command=self.discovery_results_text.yview)

        # Buttons below output
        scan_btn = tk.Button(frame_buttons, text="Scan Target Network", command=self.start_network_scan,
                             bg=button_color, fg="black", font=(word_style, 12))
        scan_btn.grid(row=0, column=0, padx=10, pady=5)

        scan_own_ip_btn = tk.Button(frame_buttons, text="Scan Own Network", command=self.scan_own_network,
                                    bg=button_color, fg="black", font=(word_style, 12))
        scan_own_ip_btn.grid(row=0, column=1, padx=10, pady=5)

        # Notifications checkbox
        self.notify_var = tk.BooleanVar()
        tk.Checkbutton(frame_buttons, text="Enable Notifications", variable=self.notify_var, font=(word_style, 12),
                       bg=frame_color, fg=text_color, activebackground=frame_color, activeforeground=text_color,
                       selectcolor="black").grid(row=0, column=5, padx=10, pady=5)

        # Progress bar
        self.progress_bar = ttk.Progressbar(frame_progress, orient=tk.HORIZONTAL, length=400, mode='indeterminate')
        self.progress_bar.pack(pady=10)

        # Status bar
        self.status_label = tk.Label(frame_status, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W,
                                     bg=text_color, fg="white")
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def is_valid_network_range(self, network_range):
        try:
            ipaddress.IPv4Network(network_range, strict=False)
            return True
        except ValueError:
            return False

    def start_network_scan(self):
        network_range = self.discovery_ip_entry.get()

        if not network_range:
            messagebox.showerror("Error", "Network Range is required (e.g., 192.168.1.0/24)")
            return

        if not self.is_valid_network_range(network_range):
            messagebox.showerror("Error", "Please enter a valid network range in CIDR format (e.g., 192.168.1.0/24)")
            return

        self.status_label.config(text=f"Scanning network ({network_range})...")
        self.discovery_results_text.delete("1.0", tk.END)
        self.discovery_results_text.insert("end", f"Scanning network ({network_range})...\n")

        self.disable_tabs()  # Disable all tabs when the scan starts

        scan_command = ['nmap', '-T4', '-O', 'vv', network_range]  # Ping scan for network discovery

        # Start scan in a separate thread
        self.progress_bar.start()
        scan_thread = threading.Thread(target=self.run_network_scan, args=(scan_command,))
        scan_thread.start()

    def run_network_scan(self, scan_command):
        try:
            result = subprocess.run(scan_command, capture_output=True, text=True)
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to run network scan: {result.stderr}")
                return

            self.parse_nmap_output(result.stdout)

            self.status_label.config(text="Network discovery completed successfully")

            if self.notify_var.get():
                self.notify_user("Network discovery completed successfully.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            self.progress_bar.stop()
            self.enable_tabs()  # Enable all tabs once the scan completes

    def parse_nmap_output(self, output):
        self.discovery_results_text.insert("end", "Discovered Devices:\n")

        # Find discovered IP addresses
        live_hosts = re.findall(r'Nmap scan report for ([\d.]+)', output)

        if live_hosts:
            for host in live_hosts:
                # Default OS info for Router and Broadcast IPs
                if host.endswith('.1'):
                    os_info = "Default Gateway(Router)"
                elif host.endswith('.254'):
                    os_info = "Broadcast"
                else:
                    # Extract OS information specific to this host block
                    os_block_pattern = re.compile(r'Nmap scan report for {}.*?(\n\n|\Z)'.format(re.escape(host)),
                                                  re.DOTALL)
                    os_block_match = os_block_pattern.search(output)

                    if os_block_match:
                        host_block = os_block_match.group(0)

                        # First try to get "OS details"
                        os_info_match = re.search(r'OS details: ([^\n]+)', host_block)
                        if os_info_match:
                            os_info = os_info_match.group(1).strip()
                        else:
                            # If no OS details, try to get "Running"
                            running_match = re.search(r'Running: ([^\n]+)', host_block)
                            if running_match:
                                os_info = running_match.group(1).strip()
                            else:
                                os_info = "OS not detected"

                # Insert the IP and its associated OS info
                self.discovery_results_text.insert("end", f"IP: {host}\n   OS: {os_info}\n")
        else:
            self.discovery_results_text.insert("end", "No live devices found.\n")

    def scan_own_network(self):
        try:
            # Get Wi-Fi adapter's IP and determine the network range
            own_ip, network_range = self.get_wifi_network_range()

            if not network_range:
                return

            self.discovery_ip_entry.delete(0, tk.END)
            self.discovery_ip_entry.insert(0, network_range)

            self.start_network_scan()

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    import ipaddress

    def get_wifi_network_range(self):
        try:
            net_if_addrs = psutil.net_if_addrs()
            wifi_interface_keywords = ['Wi-Fi', 'WLAN', 'Wireless', 'wlan', 'WiFi']

            for interface, addresses in net_if_addrs.items():
                if any(keyword in interface for keyword in wifi_interface_keywords):
                    for addr in addresses:
                        if addr.family == socket.AF_INET:
                            local_ip = addr.address
                            subnet_mask = addr.netmask

                            # Check if the IP address falls within an ignored range
                            if (local_ip.startswith("172.") or local_ip.startswith("192.168.0.")):
                                continue  # Skip this IP and continue with the next one

                            # Calculate the CIDR network range (e.g., 192.168.1.0/24)
                            ip_interface = ipaddress.IPv4Interface(f"{local_ip}/{subnet_mask}")
                            network_range = str(ip_interface.network)
                            return local_ip, network_range

            raise Exception("Could not find Wi-Fi adapter with a valid IP address.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to get Wi-Fi IP and network range: {e}")
            return None, None

    def disable_tabs(self):
        """Disable all tabs except the currently active one to prevent switching during scans."""
        current_tab = self.notebook.index(self.notebook.select())  # Get the index of the current tab
        for i in range(self.notebook.index("end")):  # Disable all tabs except the current one
            if i != current_tab:
                self.notebook.tab(i, state="disabled")

    def enable_tabs(self):
        """Enable all tabs after the scan completes."""
        for i in range(self.notebook.index("end")):  # Enable all tabs
            self.notebook.tab(i, state="normal")

    def notify_user(self, message):
        """Send a system notification."""
        notification.notify(title='Network Discovery', message=message, timeout=10)