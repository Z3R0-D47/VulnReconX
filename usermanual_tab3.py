import tkinter as tk

class UserManualPage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.configure(bg='#DFD3C3')  # Set the background of the frame
        self.setup_ui()

    def setup_ui(self):
        # Define the new color palette and font style
        bg_color = "#F8EDE3"
        frame_color = "#DFD3C3"
        text_color = "#C5705D"
        word_style = "Calibri"

        # Create a frame for the Help content with consistent color
        frame_help = tk.Frame(self, bg=frame_color, padx=20, pady=10)
        frame_help.pack()

        # Scrollbar for help text
        help_scrollbar = tk.Scrollbar(frame_help)
        help_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Text box for displaying help content with consistent color and font
        help_text_box = tk.Text(frame_help, wrap=tk.WORD, yscrollcommand=help_scrollbar.set, font=(word_style, 12),
                                height=30, width=80, bg=bg_color, fg=text_color)
        help_text_box.pack(padx=10, pady=10)

        # Configure the scrollbar
        help_scrollbar.config(command=help_text_box.yview)

        # Insert the help text content with slight modification
        help_text_box.insert("1.0", """
VulnReconX - User Manual

1. **Entering IP Address/Network:**
    - Input a valid IP address or network range in the format:
    - Example: 192.168.1.1 or 192.168.1.0/24.

2. **Configure Scan Options:**
    - Use the 'Configure Scan' button to select scan options:
      - **Verbose Mode (-vv):** Enables detailed scan logs.
      - **OS Detection (-O):** Identifies the operating system on target devices.
      - **Service Version Detection (-sV):** Determines version information for open services.

3. **Network Discovery:**
    - Enter a valid network range and click 'Start Scan' to discover live hosts within that range.
    - Use 'Scan Own Network' to automatically detect and scan your own local network.

4. **Self-IP Scanning:**
    - Click the 'Scan Own IP' button to quickly scan your own device's IP for open ports and vulnerabilities.

5. **Saving Results:**
    - After a scan, click 'Save Results' to store the findings in a text file for later analysis.

6. **Interpreting Results:**
    - The results box will display discovered devices, open ports, services, and associated vulnerabilities.
    - Color-coded severity ratings (High, Medium, Low) will help prioritize any security issues.
    -Note: Severity ratings indicate potential risk but do not guarantee exploitation. System configuration and mitigation measures may reduce the actual threat.    

7. **Checking CVE Information:**
    - For detailed vulnerability information, visit the National Vulnerability Database (NVD) here:
      https://nvd.nist.gov

**Troubleshooting:**
    - Ensure **Nmap** is properly installed on your system.
    - Check the accuracy of the IP or network range if scans fail.
    - Some scans may require administrator privileges, especially for OS detection and service version scans.

        """)

        # Make the help text box read-only
        help_text_box.config(state=tk.DISABLED)
