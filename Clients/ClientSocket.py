import socket
import ssl
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from PIL import Image, ImageTk

class ClientSocket:
    """Client class"""
    
    def __init__(self, host: str, port: int, use_tls: bool = False) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_tls:
            self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.context.load_verify_locations('Server/server.crt')  # Path to server.crt
    
    def update_active_users(self, message):
        """Update the active users list in the GUI."""
        self.active_users_text.config(state=tk.NORMAL)
        self.active_users_text.delete(1.0, tk.END)  # Clear existing content
        self.active_users_text.insert(tk.END, message)
        self.active_users_text.config(state=tk.DISABLED)

    def receive_messages(self):
        while True:
            try:
                response = self.client_socket.recv(1024)
                if not response:
                    print(f"Server has closed the connection.")
                    break
                message = response.decode('utf-8')
                
                if message.startswith("Active Users"):
                    self.text_area.after(0,self.update_active_users, message)
                else:self.text_area.after(0, self.insert_message, f"Server: {message}\n")
            except Exception as e:
                print(f"An error occurred while receiving a message: {e}")
                break

    def insert_message(self, message):
        """Insert message into the text area safely from another thread."""
        self.text_area.insert(tk.END, message)
        self.text_area.yview(tk.END)

    def connect_server(self, username, password, action):
        try:
            if self.use_tls:
            # Only wrap the socket if it's a valid socket object
                if not self.client_socket._closed:  # Check if the socket is open (this is just an example check)
                    self.client_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.host)
            else:
                print(f"Error: Socket is already closed before wrapping with SSL.")
                return
            
            self.client_socket.connect((self.host, self.port))  # Only after wrapping or creating the socket
            self.client_socket.sendall(action.encode('utf-8'))
            self.client_socket.sendall(username.encode('utf-8'))
            self.client_socket.sendall(password.encode('utf-8'))

            auth_response = self.client_socket.recv(1024).decode('utf-8')
            
            if "successful" in auth_response:
                self.connect_button.config(state=tk.DISABLED)  # Disable button on successful connection
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                self.client_socket.close()
                self.text_area.after(0, self.insert_message, "Authentication failed. Connection closed.\n")

        except Exception as e:
            print(f"Error connecting to server: {e}")
            self.text_area.after(0, self.insert_message, f"Error: {e}\n")
        
    def send_message(self, message):
        if message.lower() == 'end':
            self.client_socket.sendall(message.encode('utf-8'))
            self.client_socket.close()
            self.window.quit()
        else:
            self.client_socket.sendall(message.encode('utf-8'))

    def create_gui(self):
        # Window Configuration
        self.window = tk.Tk()
        self.window.title("CLINET")
        self.window.configure(bg="#0b3595")
        self.window.geometry("800x600")  # Adjust window size as needed

        # --- Background Setup ---
        self.background_image = Image.open('Clients/balcony-8865325_1280.jpg')
        self.background_photo = ImageTk.PhotoImage(self.background_image)
        self.background_label = tk.Label(self.window, image=self.background_photo)
        self.background_label.place(relwidth=1, relheight=1)  # Cover the entire window

        # --- Chat Area ---
        self.text_area = scrolledtext.ScrolledText(
            self.window, 
            width=50, 
            height=20, 
            wrap=tk.WORD, 
            bg="#0b3595", 
            fg="white", 
            font=("Caslon Antique", 20)
        )
        self.text_area.grid(row=0, column=0, padx=10, pady=10, columnspan=2)

        # --- Active Users Area ---
        self.active_users_label = tk.Label(
            self.window,
            text="Active Users",
            bg="#0b3595",
            fg="white",
            font=("Caslon Antique", 20, "bold")
        )
        self.active_users_label.grid(row=2, column=2, padx=5, pady=(5), sticky="nsew")

        self.active_users_text = scrolledtext.ScrolledText(
            self.window, 
            width=30, 
            height=20, 
            wrap=tk.WORD, 
            bg="#0b3595", 
            fg="white", 
            font=("Caslon Antique", 20)
        )
        self.active_users_text.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")

        # --- User Input Section ---
        self.username_label = tk.Label(
            self.window, 
            text="Username:", 
            bg="#0b3595", 
            fg="white", 
            font=("Caslon Antique", 20, "bold")
        )
        self.username_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")

        self.username_entry = tk.Entry(
            self.window, 
            width=20, 
            bg="#420018", 
            fg="white", 
            insertbackground="black", 
            font=("Caslon Antique", 20)
        )
        self.username_entry.grid(row=2, column=1, padx=0, pady=5, sticky="w")

        self.password_label = tk.Label(
            self.window, 
            text="Password:", 
            bg="#0b3595", 
            fg="white", 
            font=("Caslon Antique", 20, "bold")
        )
        self.password_label.grid(row=3, column=0, padx=10, pady=5, sticky="e")

        self.password_entry = tk.Entry(
            self.window, 
            width=20, 
            show="*", 
            bg="#420018", 
            fg="white", 
            insertbackground="black", 
            font=("Caslon Antique", 20)
        )
        self.password_entry.grid(row=3, column=1, padx=0, pady=5, sticky="w")

        # --- User Actions (Login/Register) ---
        self.action_var = tk.StringVar(value="login")  # Default action is login

        self.login_rb = tk.Radiobutton(
            self.window, 
            text="Login", 
            command=self.action_var, 
            value="Login", 
            bg="#0b3595", 
            fg="white", 
            font=("Caslon Antique", 15)
        )
        self.login_rb.grid(row=4, column=0, padx=5, pady=5, sticky="e")

        self.register_rb = tk.Radiobutton(
            self.window, 
            text="Register", 
            command=self.action_var, 
            value="Register", 
            bg="#0b3595", 
            fg="white", 
            font=("Caslon Antique", 15)
        )
        self.register_rb.grid(row=4, column=1, padx=0, pady=5, sticky="w")

        self.connect_button = tk.Button(
            self.window, 
            text="Connect", 
            command=self.connect, 
            bg="#0b3595", 
            fg="white", 
            font=("Caslon Antique", 20, "bold")
        )
        self.connect_button.grid(row=4, column=2, padx=(0), pady=5, sticky="w")

        # --- Message Input Section ---
        self.message_label = tk.Label(
            self.window, 
            text="Enter message:", 
            bg="#0b3595", 
            fg="white", 
            font=("Caslon Antique", 20, "bold")
        )
        self.message_label.grid(row=6, column=0, padx=10, pady=5, sticky="e")

        self.message_entry = tk.Entry(
            self.window, 
            width=30, 
            bg="#420018", 
            fg="white", 
            insertbackground="black", 
            font=("Caslon Antique", 20)
        )
        self.message_entry.grid(row=6, column=1, padx=10, pady=5)

        self.send_button = tk.Button(
            self.window, 
            text="Send", 
            command=self.send_chat_message, 
            bg="#0b3595", 
            fg="white", 
            font=("Caslon Antique", 20, "bold")
        )
        self.send_button.grid(row=6, column=2, padx=10, pady=5, sticky="w")

        # --- Grid Configuration ---
        self.window.grid_rowconfigure(0, weight=1)  # For chat area
        self.window.grid_rowconfigure(1, weight=1)  # For active users label
        self.window.grid_columnconfigure(2, weight=1)  # Adjust active users column

        # Start the main loop
        self.window.mainloop()

    def connect(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        action = self.action_var.get()

        if username and password:
            self.connect_server(username, password, action)
        else: 
            self.text_area.insert(tk.END, "Please enter both username and password.\n")
            self.text_area.yview(tk.END)

    def send_chat_message(self):
        message = self.message_entry.get()
        if message.lower() == 'end':
            self.client_socket.sendall(message.encode('utf-8'))
            self.client_socket.close()  # Properly close connection when ending chat
            self.window.quit()  # Close the client window
        else:
            self.client_socket.sendall(message.encode('utf-8'))
            self.text_area.insert(tk.END, f"You: {message}\n")
            self.text_area.yview(tk.END)
            self.message_entry.delete(0, tk.END)
        
if __name__ == "__main__":
    host = '69.43.66.35'
    port = 27017
    client = ClientSocket(host=host, port=port, use_tls=True)
    client.create_gui()
