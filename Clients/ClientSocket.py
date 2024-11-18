import socket
import ssl
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

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
            
    def receive_messages(self):
        while True:
            try:
                response = self.client_socket.recv(1024)
                if not response:
                    print("Server has closed the connection.")
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
        """Connect to the server and authenticate"""
        try:
            if self.use_tls:
                self.client_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.host)

            self.client_socket.connect((self.host, self.port))

            # Send username and password to server
            self.client_socket.sendall(action.encode('ut-8'))
            self.client_socket.sendall(username.encode('utf-8'))
            self.client_socket.sendall(password.encode('utf-8'))

            # Receive authentication response from server
            auth_response = self.client_socket.recv(1024).decode('utf-8')
            self.text_area.after(0, self.insert_message, f"{auth_response}\n")

            if "successful" in auth_response:
                # Disable the connect button after successful connection
                self.connect_button.config(state=tk.DISABLED)
                # Start receiving messages from the server in a separate thread
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
        self.window = tk.Tk()
        self.window.title("Chat Client")
        self.window.configure(bg="#003366")
        self.action_var = tk.StringVar(value="login")

        # ScrolledText widget for chat logs
        self.text_area = scrolledtext.ScrolledText(self.window, width=50, height=20, wrap=tk.WORD)
        self.text_area.grid(row=0, column=0, padx=10, pady=10)

        # Active user display
        self.active_users_label = tk.Label(self.window, text="Active Users", bg="#003366", fg="white", font=("Helvetica", 12, "bold"))
        self.active_users_label.grid(row=1, column=2, padx=5, pady=5, sticky="n")  # Align to the top

        self.active_users_text = scrolledtext.ScrolledText(self.window, width=30, height=20, wrap=tk.WORD, state=tk.DISABLED)
        self.active_users_text.grid(row=0, column=2, padx=5, pady=5)

        # Entry for username and password
        self.username_label = tk.Label(self.window, text="Username: ", bg="#003366", fg="white", font=("Helvetica", 12, "bold"))
        self.username_label.grid(row=2, column=0, padx=10)
        self.username_entry = tk.Entry(self.window, width=30, bg="#1a2936", fg="white", insertbackground="white", font=("Helvetica", 12))
        self.username_entry.grid(row=2, column=1, padx=10)

        self.password_label = tk.Label(self.window, text="Password: ", bg="#003366", fg="white", font=("Helvetica", 12, "bold"))
        self.password_label.grid(row=3, column=0, padx=10)
        self.password_entry = tk.Entry(self.window, width=30, show="*", bg="#1a2936", fg="white", insertbackground="white", font=("Helvetica", 12))
        self.password_entry.grid(row=3, column=1, padx=10)

        self.action_var = tk.StringVar(value="login")  # Default action is login
        self.login_rb = tk.Radiobutton(self.window, text="Login", variable=self.action_var, value="login", bg="#003366", fg="white")
        self.login_rb.grid(row=4, column=0, padx=10)
        self.register_rb = tk.Radiobutton(self.window, text="Register", variable=self.action_var, value="register", bg="#003366", fg="white")
        self.register_rb.grid(row=5, column=0, padx=10)

        self.connect_button = tk.Button(self.window, text="Connect", command=self.connect, bg="#005288", fg="white", font=("Helvetica", 12, "bold"))
        self.connect_button.grid(row=6, column=1, padx=10, pady=10)

        # Entry for chat messages
        self.message_label = tk.Label(self.window, text="Enter message:", bg="#003366", fg="white", font=("Helvetica", 12, "bold"))
        self.message_label.grid(row=7, column=0, padx=10)
        self.message_entry = tk.Entry(self.window, width=30, bg="#1a2936", fg="white", insertbackground="white", font=("Helvetica", 12))
        self.message_entry.grid(row=7, column=1, padx=10)

        self.send_button = tk.Button(self.window, text="Send", command=self.send_chat_message, bg="#005288", fg="white", font=("Helvetica", 12, "bold"))
        self.send_button.grid(row=7, column=2, padx=10)

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
        if message:
            self.send_message(message)
            self.text_area.insert(tk.END, f"You: {message}\n")
            self.text_area.yview(tk.END)
            self.message_entry.delete(0, tk.END)
        else: 
            self.text_area.insert(tk.END, "Please enter a message to send.\n")
            self.text_area.yview(tk.END)
        
if __name__ == "__main__":
    host = 'localhost'
    port = 1200
    client = ClientSocket(host=host, port=port, use_tls=True)
    client.create_gui()
