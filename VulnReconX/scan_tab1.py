import re
import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import sqlite3
import threading
import socket
import datetime
from plyer import notification
import psutil
import os

class ScanPage(tk.Frame):
    def __init__(self, parent, notebook):
        super().__init__(parent)
        self.notebook = notebook  # Pass the notebook reference to control tab switching
        self.configure(bg='#DFD3C3')  # Set the background of the frame
        self.verbose_mode_var = tk.BooleanVar()
        self.os_scan_mode_var = tk.BooleanVar()
        self.service_version_var = tk.BooleanVar()
        self.setup_ui()

    def setup_ui(self):
        # Define the new color palette and font style
        bg_color = "#F8EDE3"
        frame_color = "#DFD3C3"
        button_color = "#D0B8A8"
        text_color = "#C5705D"
        word_style = "Calibri"

        # Frames for layout with the new color palette
        frame_header = tk.Frame(self, bg=frame_color, pady=10)
        frame_header.pack()

        frame_scan = tk.Frame(self, bg=frame_color, padx=20, pady=10)
        frame_scan.pack()

        frame_output = tk.Frame(self, bg=frame_color, padx=20, pady=10)
        frame_output.pack()

        frame_buttons = tk.Frame(self, bg=frame_color, pady=10)
        frame_buttons.pack()

        frame_progress = tk.Frame(self, bg=frame_color, pady=20)
        frame_progress.pack()

        frame_status = tk.Frame(self, bg=frame_color, padx=20, pady=10)
        frame_status.pack(side=tk.BOTTOM, fill=tk.X)

        # Header
        header_label = tk.Label(frame_header, text="VulnReconX", font=(word_style, 25, "bold"), pady=10,
                                bg=frame_color, fg=text_color)
        header_label.pack()

        # Scan input
        tk.Label(frame_scan, text="IP Address or Network:", font=(word_style, 12), bg=frame_color, fg=text_color).grid(
            row=0, column=0, padx=10, pady=5)
        self.ip_entry = tk.Entry(frame_scan, font=(word_style, 14), width=30, bg=bg_color,
                                 fg=text_color)  # Custom colors
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5)

        # Progress bar
        self.progress_bar = ttk.Progressbar(frame_progress, orient=tk.HORIZONTAL, length=400, mode='indeterminate')
        self.progress_bar.pack(pady=10)

        # Output text box with scrollbar
        scrollbar = tk.Scrollbar(frame_output)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Set custom colors for the output text box
        self.results_text = tk.Text(frame_output, wrap=tk.WORD, yscrollcommand=scrollbar.set, font=(word_style, 12),
                                    height=15, width=70, bg=bg_color, fg=text_color)
        self.results_text.pack(padx=10, pady=10)
        scrollbar.config(command=self.results_text.yview)

        # Buttons with the new palette
        config_button = tk.Button(frame_buttons, text="Configure Scan", command=self.open_configuration_window,
                                  bg=button_color, fg="black", font=(word_style, 12))
        config_button.grid(row=0, column=0, padx=10, pady=5)

        start_scan_btn = tk.Button(frame_buttons, text="Scan Target IP", command=self.start_scan, bg=button_color,
                                   fg="black", font=(word_style, 12))
        start_scan_btn.grid(row=0, column=1, padx=10, pady=5)

        own_ip_btn = tk.Button(frame_buttons, text="Scan Own IP", command=self.scan_own_ip, bg=button_color, fg="black",
                               font=(word_style, 12))
        own_ip_btn.grid(row=0, column=2, padx=10, pady=5)

        save_button = tk.Button(frame_buttons, text="Save Results", command=self.save_results, bg=button_color,
                                fg="black", font=(word_style, 12))
        save_button.grid(row=0, column=4, padx=10, pady=5)

        # Notifications checkbox
        self.notify_var = tk.BooleanVar()
        tk.Checkbutton(frame_buttons, text="Enable Notifications", variable=self.notify_var, font=(word_style, 12),
                       bg=frame_color, fg=text_color, activebackground=frame_color, activeforeground=text_color,
                       selectcolor="black").grid(row=0, column=5, padx=10, pady=5)

        # Status bar
        self.status_label = tk.Label(frame_status, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W,
                                     bg=text_color, fg="white")
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        # Configure text colors for result tags
        self.results_text.tag_configure("high", foreground="red")
        self.results_text.tag_configure("medium", foreground="orange")
        self.results_text.tag_configure("low", foreground="green")
        self.results_text.tag_configure("os", foreground="blue")

    def is_valid_ip_or_network(self, ip):
        pattern_ip = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$')
        pattern_network = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$')
        if pattern_ip.match(ip):
            parts = ip.split(".")
            for part in parts:
                if int(part) > 255:
                    return False
            return True
        if pattern_network.match(ip):
            return True
        return False

    def start_scan(self):
        ip = self.ip_entry.get()

        if not ip:
            messagebox.showerror("Error", "IP Address is required")
            return

        if not self.is_valid_ip_or_network(ip):
            messagebox.showerror("Error",
                                 "Please enter a valid IP address or network (e.g., 192.168.1.1 or 192.168.1.0/24)")
            return

        # Disable tab switching
        self.disable_tabs()

        # Clear previous results before new scan
        self.results_text.delete("1.0", tk.END)

        # Indicate scan in progress
        self.status_label.config(text="Scanning in progress...")

        # Build the nmap command based on selected options
        scan_command = ['nmap']
        if self.verbose_mode_var.get():
            scan_command.append('-vv')  # Verbose mode
        if self.os_scan_mode_var.get():
            scan_command.append('-O')  # OS detection
        if self.service_version_var.get():
            scan_command.append('-sV')  # Service version detection
        scan_command.append(ip)

        # Start the scan in a separate thread
        self.progress_bar.start()
        scan_thread = threading.Thread(target=self.run_nmap_scan, args=(scan_command,))
        scan_thread.start()

    def run_nmap_scan(self, scan_command):
        try:
            # Get the directory where the current script is running
            base_dir = os.path.dirname(os.path.abspath(__file__))

            # Create the path to the database using a relative path
            db_path = os.path.join(base_dir, 'database', 'recommendations.db')

            # Connect to the SQLite database
            conn_combined = sqlite3.connect(db_path)
            cursor_combined = conn_combined.cursor()

            # Run the nmap command and capture the output
            result = subprocess.run(scan_command, capture_output=True, text=True)
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to run nmap: {result.stderr}")
                return

            # Simplify and display the results
            self.simplify_results(result.stdout, cursor_combined)

            # Update the status label after the scan completes
            self.status_label.config(text="Scan completed successfully")

            # Send a notification if enabled
            if self.notify_var.get():
                self.notify_user("Scan completed. Check results.")

            # Close the database connection
            conn_combined.close()

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            # Enable tab switching after the scan is complete
            self.enable_tabs()
            self.progress_bar.stop()
            
    def scan_own_ip(self):
        try:
            # Disable tab switching
            self.disable_tabs()

            # Iterate over the network interfaces using psutil
            addrs = psutil.net_if_addrs()

            # We will store the Wi-Fi IP here once we find it
            own_ip = None

            # Look for a network interface containing the word "Wi-Fi"
            for interface, addresses in addrs.items():
                if "Wi-Fi" in interface or "wlan" in interface.lower():  # Adjust for possible names like "wlan"
                    for addr in addresses:
                        if addr.family == socket.AF_INET:  # IPv4 address
                            own_ip = addr.address  # Store the IP address

            if not own_ip:
                raise Exception("Could not determine IP address from Wi-Fi adapter.")

            # Insert the Wi-Fi adapter's IP into the IP entry field
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, own_ip)
            self.start_scan()

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            # Ensure that tabs are re-enabled if an error occurs
            self.enable_tabs()

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

    def simplify_results(self, scan_output, cursor):
        # Enable the Text widget to insert content (change from read-only)
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)  # Clear previous results

        open_ports = re.findall(r'(\d+)/tcp\s+open\s+([\w]+)', scan_output)

        if open_ports:
            self.results_text.insert("end", "We found some open ports on your system:\n\n")
            for port, service in open_ports:
                port_num = int(port)
                severity = self.get_severity_for_port(port_num)

                # Apply color coding based on severity
                if severity == "High":
                    self.results_text.insert("end",
                                             f"⚠ Port {port_num} ({service.capitalize()}): Severity - {severity}\n",
                                             ("high",))
                elif severity == "Medium":
                    self.results_text.insert("end",
                                             f"⚠ Port {port_num} ({service.capitalize()}): Severity - {severity}\n",
                                             ("medium",))
                else:
                    self.results_text.insert("end",
                                             f"⚠ Port {port_num} ({service.capitalize()}): Severity - {severity}\n",
                                             ("low",))

                # Fetch recommendation, vulnerability info, and further investigation from the database
                recommendation, vulnerability_info, further_investigation = self.fetch_combined_data(service, cursor)

                self.results_text.insert("end", f"   👉 Recommended Action: {recommendation}\n")
                self.results_text.insert("end", f"   🔍 CVE: {vulnerability_info}\n")
                self.results_text.insert("end", f"   ❓ Further Investigation: {further_investigation}\n\n")
        else:
            self.results_text.insert("end", "🎉 No open ports found. Your system looks secure!\n")

        # Show detected OS if found
        if "Running" in scan_output:
            os_info = re.search(r'Running: (.+)', scan_output)
            if os_info:
                self.results_text.insert("end", f"\nOperating System Detected: {os_info.group(1)}\n", ("os",))

        # Show simplified verbose output if enabled
        if self.verbose_mode_var.get():
            verbose_lines = [line for line in scan_output.splitlines() if "open" in line or "service" in line]
            self.results_text.insert("end",
                                     "\n🔍 Detailed (Verbose) Output (Simplified):\n" + "\n".join(verbose_lines) + "\n")

        # Configure text tag colors
        self.results_text.tag_configure("high", foreground="red")
        self.results_text.tag_configure("medium", foreground="orange")
        self.results_text.tag_configure("low", foreground="green")
        self.results_text.tag_configure("os", foreground="blue")

        # Make the Text widget read-only again
        self.results_text.config(state=tk.DISABLED)

    def get_severity_for_port(self, port):
        high_risk_ports = {22, 23, 25, 80, 443, 3389, 135, 139, 445}
        medium_risk_ports = {21, 110, 143, 808, 902, 912}
        if port in high_risk_ports:
            return "High"
        elif port in medium_risk_ports:
            return "Medium"
        else:
            return "Low"

    def fetch_combined_data(self, service, cursor):
        cursor.execute("SELECT recommendation, vulnerability_info, further_investigation FROM recommendations WHERE LOWER(service)=?", (service.lower(),))
        row = cursor.fetchone()
        if row:
            return row[0] or "No recommendation available.", row[1] or "No known vulnerabilities.", row[2] or "No further investigation steps available."
        return "No recommendation available.", "No known vulnerabilities.", "No further investigation steps available."

    def notify_user(self, message):
        notification.notify(title='Scan Completed', message=message, timeout=10)

    def save_results(self):
        # Check if there are scan results available
        if self.results_text.get("1.0", tk.END).strip() == "":
            messagebox.showerror("Error", "No scan results available to save.")
            return

        # Define the folder path where the results will be saved
        folder_path = 'scan_results'  # Change this to the folder name you prefer
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)  # Create the folder if it doesn't exist

        # Generate the file name based on the current time
        current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name = f'{folder_path}/scan_results_{current_time}.txt'  # Save in the folder

        try:
            # Write the scan results into the file using UTF-8 encoding
            with open(file_name, 'w', encoding='utf-8') as file:
                file.write(self.results_text.get("1.0", tk.END))
            messagebox.showinfo("Saved", f"Scan results saved to {file_name}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving the file: {e}")

    def open_configuration_window(self):
        # Define the same color palette and font style used in the main UI
        bg_color = "#F8EDE3"
        frame_color = "#DFD3C3"
        button_color = "#D0B8A8"
        text_color = "#C5705D"
        word_style = "Calibri"

        # Create the configuration window
        config_window = tk.Toplevel(self)
        config_window.title("Configure Scan Options")
        config_window.geometry("400x300")
        config_window.configure(bg=frame_color)  # Set background color

        # Header label
        tk.Label(config_window, text="Select Scan Options", font=(word_style, 14), bg=frame_color, fg=text_color).pack(
            pady=10)

        # Checkbuttons for scan options with consistent colors and font
        tk.Checkbutton(config_window, text="Verbose Mode (-vv)", variable=self.verbose_mode_var, font=(word_style, 12),
                       bg=frame_color, fg=text_color, selectcolor=button_color).pack(pady=5)
        tk.Checkbutton(config_window, text="OS Detection (-O)", variable=self.os_scan_mode_var, font=(word_style, 12),
                       bg=frame_color, fg=text_color, selectcolor=button_color).pack(pady=5)
        tk.Checkbutton(config_window, text="Service Version Detection (-sV)", variable=self.service_version_var,
                       font=(word_style, 12),
                       bg=frame_color, fg=text_color, selectcolor=button_color).pack(pady=5)

        # Save button with the same style
        tk.Button(config_window, text="Save Configuration", command=config_window.destroy, bg=button_color, fg="black",
                  font=(word_style, 12)).pack(pady=20)
