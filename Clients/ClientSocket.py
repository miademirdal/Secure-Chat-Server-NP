import socket
import ssl
import threading
import tkinter as tk
from tkinter import scrolledtext

class ClientSocket:
    """Client class"""
    
    def __init__(self, host: str, port: int, use_tls: bool = False) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_tls:
            self.context = ssl.create_default_context()
            
    def receive_messages(self):
        while True:
            try:
                response = self.client_socket.recv(1024)
                if not response:
                    print("Server has closed the connection.")
                    break
                self.text_area.insert(tk.END, f"Server: {response.decode('utf-8')}\n")
                self.text_area.yview(tk.END)
            except Exception as e:
                print(f"An error occurred while receiving a message: {e}")
                break
            
    def connect_server(self, username, password):
        """Connect to the server and authenticate"""
        try:
            if self.use_tls:
                self.client_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.host)

            self.client_socket.connect((self.host, self.port))

            # Send username and password to server
            self.client_socket.sendall(username.encode('utf-8'))
            self.client_socket.sendall(password.encode('utf-8'))

            # Receive authentication response from server
            auth_response = self.client_socket.recv(1024).decode('utf-8')
            self.text_area.insert(tk.END, f"{auth_response}\n")
            self.text_area.yview(tk.END)

            if "successful" in auth_response:
                # Start receiving messages from the server in a separate thread
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                self.client_socket.close()

        except Exception as e:
            print(f"Error connecting to server: {e}")
            self.text_area.insert(tk.END, f"Error: {e}\n")
        
    def send_message(self, message):
        if message.lower() == 'end':
            self.client_socket.sendall(message.encode('utf-8'))
            self.client_socket.close()
            self.window.quit()
        else:
            self.client_socket.sendall(message.encode('utf-8'))


    def create_gui(self): 
        self.window = tk.Tk()
        self.window.title("Chat Clinet")

        # ScrolledText widget for chat logs
        self.text_area = scrolledtext.ScrolledText(self.window, width = 50, height = 20, wrap=tk.WORD)
        self.text_area.grid(row=0, column=0, padx=10, pady=10)

        # Entry for username and password
        self.username_label = tk.Label(self.window, text="Username: ")
        self.username_label.grid(row=1, column=0, padx=10)
        self.username_entry = tk.Entry(self.window, width=30)
        self.username_entry.grid(row=1, column=1, padx=10)

        self.password_label = tk.Label(self.window, text="Password: ")
        self.password_label.grid(row=2, column=0, padx=10)
        self.password_entry = tk.Entry(self.window, width=30, show="*")
        self.password_entry.grid(row=2, column=1, padx=10)

        self.connect_button = tk.Button(self.window, text="Connect", command=self.connect)
        self.connect_button.grid(row=3, column=1, padx=10, pady=10)

        #Entry for chat messages
        self.message_label = tk.Label(self.window, text="Enter message:")
        self.message_label.grid(row=4, column=0, padx=10)
        self.message_entry = tk.Entry(self.window, width=30)
        self.message_entry.grid(row=4, column=1, padx=10)

        self.send_button = tk.Button(self.window, text="Send", command=self.send_chat_message)
        self.send_button.grid(row=4, column=2, padx=10)

        self.window.mainloop()

    def connect(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            self.connect_server(username, password)
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