import win32security
import tkinter as tk
from tkinter import messagebox

class LoginSystem:
    def __init__(self, root):
        self.root = root
        self.root.configure(bg='#DFD3C3')  # Set the background of the root window
        self.root.title("Login System")
        self.root.geometry("400x300")

        # Define the new color palette and font style
        self.bg_color = "#F8EDE3"
        self.frame_color = "#DFD3C3"
        self.button_color = "#D0B8A8"
        self.text_color = "#C5705D"
        self.word_style = "Calibri"

        self.create_ui()

    # Function to authenticate user using Windows credentials
    def login_user(self, username, password):
        try:
            # Attempt to log on the user using Windows credentials
            handle = win32security.LogonUser(
                username,
                None,  # Use None for the local computer, or provide the domain
                password,
                win32security.LOGON32_LOGON_INTERACTIVE,
                win32security.LOGON32_PROVIDER_DEFAULT
            )
            # If successful, return True and close the login window
            messagebox.showinfo("Success", "Login successful!")
            self.root.destroy()  # Close the login window
            return True
        except win32security.error as e:
            # Display an error message if authentication fails
            messagebox.showerror("Error", "Login failed: Invalid username or password.")
            return False

    # Function to create the login UI
    def create_ui(self):
        # Create frames for the UI
        frame_header = tk.Frame(self.root, bg=self.frame_color, pady=10)
        frame_header.pack()

        frame_body = tk.Frame(self.root, bg=self.frame_color, padx=20, pady=10)
        frame_body.pack()

        frame_buttons = tk.Frame(self.root, bg=self.frame_color, pady=10)
        frame_buttons.pack()

        # Header
        header_label = tk.Label(frame_header, text="VulnReconX", font=(self.word_style, 20, "bold"), pady=10,
                                bg=self.frame_color, fg=self.text_color)
        header_label.pack()

        # Username and password fields
        tk.Label(frame_body, text="Username:", font=(self.word_style, 12), bg=self.frame_color, fg=self.text_color).grid(row=0, column=0, padx=10, pady=5)
        tk.Label(frame_body, text="Password:", font=(self.word_style, 12), bg=self.frame_color, fg=self.text_color).grid(row=1, column=0, padx=10, pady=5)

        username_entry = tk.Entry(frame_body, font=(self.word_style, 14), width=20, bg=self.bg_color, fg=self.text_color)
        password_entry = tk.Entry(frame_body, font=(self.word_style, 14), show="*", width=20, bg=self.bg_color, fg=self.text_color)

        username_entry.grid(row=0, column=1, padx=10, pady=5)
        password_entry.grid(row=1, column=1, padx=10, pady=5)

        # Button for login only
        tk.Button(frame_buttons, text="Login", command=lambda: self.login_user(username_entry.get(), password_entry.get()), bg=self.button_color, fg="black", font=(self.word_style, 12)).grid(row=2, column=0, pady=5)

