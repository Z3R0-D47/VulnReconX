import ctypes
import sys
import os
import tkinter as tk
from tkinter import messagebox, ttk
from authentication_system import LoginSystem
from scan_tab1 import ScanPage
from networkdiscovery_tab2 import NetworkDiscoveryPage
from usermanual_tab3 import UserManualPage

# Function to check if the script is running with admin rights
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# If not admin, prompt user for admin rights and restart the script
def require_admin_privileges():
    if not is_admin():
        # Prompt user for admin rights
        try:
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])  # Preserve existing arguments
            script_path = os.path.abspath(sys.argv[0])  # Ensure correct path is used
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}" {params}', None, 1)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to gain admin privileges: {e}")
        sys.exit()  # Exit the current instance


# Create the main GUI function
def create_main_gui():
    root = tk.Tk()
    root.title("VulnReconX")
    root.geometry("900x700")

    style = ttk.Style()
    style.configure("TNotebook", background="#DFD3C3")  # Set the background color

    # Create notebook for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(expand=1, fill="both")

    # Create and add the actual pages/tabs
    scan_tab = ScanPage(notebook, notebook)  # Link to ScanPage from scan_tab1
    discovery_tab = NetworkDiscoveryPage(notebook, notebook)  # Link to NetworkDiscoveryPage from networkdiscovery_tab2
    help_tab = UserManualPage(notebook)  # Link to HelpPage from help_tab4

    # Add tabs to the notebook
    notebook.add(scan_tab, text="Vulnerability Scan")
    notebook.add(discovery_tab, text="Network Discovery")
    notebook.add(help_tab, text="User Manual")

    root.mainloop()


# Function to start the login system before showing the main GUI
def start_login_then_gui():
    # Create the login window
    login_root = tk.Tk()
    login_app = LoginSystem(login_root)  # Create the login system instance

    def on_login_close():
        login_root.destroy()  # Close the login window
        sys.exit()  # Exit the application if the login window is closed without successful login

    login_root.protocol("WM_DELETE_WINDOW", on_login_close)  # Handle closing of login window
    login_root.mainloop()

    # After successful login, open the main application GUI
    create_main_gui()


# Main function
def main():
    # Check for admin privileges first
    require_admin_privileges()

    # Start with the login system, and after login, the main GUI will be shown
    start_login_then_gui()


# Entry point
if __name__ == "__main__":
    main()
