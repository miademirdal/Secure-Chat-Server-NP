import socket
import ssl
import threading
from threading import Lock
from pymongo import MongoClient
import bcrypt
import tkinter as tk


class ServerSocket:
    """server class"""
    hostname = 'clinet.ddns.net'
    port = 61626
    
    def __init__(self, host: str, port: int) -> None:\

        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server started on {self.host}:{self.port}")
        
        #ssl content
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile='Server/server.crt', keyfile='Server/server.key')
        
        #setup MongoDB
        self.client_db = MongoClient("mongodb://clinet.ddns.net:27017/")  # Use local MongoDB instance
        self.db = self.client_db['chat_db']
        self.user_collection = self.db['users']

        self.lock = Lock()
        self.active_users = [] # List of active users
        self.connected_clients = [] # List of connected clients
    
    def update_active_users(self):
        with self.lock:
            active_users = ', '.join(self.active_users)
            for client in self.connected_clients:
                try:
                    client.sendall(f"Active Users: {active_users}".encode('utf-8'))
                except Exception as e:
                    print(f"Error sending active users list: {e}")

    def user_storage(self, username: str, password: str) -> bool:
        if self.user_collection.find_one({"username": username}):
            return False  # Username already exists
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.user_collection.insert_one({"username": username, "password": hashed_password})
        print(f"Stored user: {username}")
        return True

        
    def user_auth(self, username: str, password: str):
        user = self.user_collection.find_one({"username": username})
        if user is None:
            print(f"User {username} not found.")
            return False  # Early return if the user is not found
    # Check if the password matches the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return True
        else:
            print(f"Incorrect password for user {username}.")
            return False
    
    def update_activity_log(self):
        print("\n--- Current Active Users ---")
        for username in self.connected_clients:
            print(f"User: {username}")
        print("---------------------------\n")
    
    def client_connect(self, client_socket):
        secure_client_socket = self.context.wrap_socket(client_socket, server_side=True)
        try:
            action = secure_client_socket.recv(1024).decode('utf-8')
            if action == "register":
                self.handle_registration(secure_client_socket)
            elif action == "login":
                self.handle_login(secure_client_socket)
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            secure_client_socket.close()
            
    def handle_registration(self, client_socket):
        while True:
            username = client_socket.recv(1024).decode('utf-8')
            password = client_socket.recv(1024).decode('utf-8')
            if self.user_storage(username, password):
                client_socket.sendall("Registration successful.".encode('utf-8'))
                break
            else:
                client_socket.sendall("Username already in use.".encode('utf-8'))

    def handle_login(self, client_socket):
        username = client_socket.recv(1024).decode('utf-8')
        password = client_socket.recv(1024).decode('utf-8')
        if self.user_auth(username, password):
            client_socket.sendall("Login successful.".encode('utf-8'))
            with self.lock:
                self.active_users.append(username)
            self.handle_chat(client_socket, username)
        else:
            client_socket.sendall("Login failed.".encode('utf-8'))
            
            # Chat functionality
        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    print(f"User {username} disconnected.")
                    self.active_users.remove(username)
                    break  # If no data is received, break the loop
                print(f"Received from client: {data.decode('utf-8')}")
                #client_socket.sendall("Server: Message Received!".encode('utf-8'))
            except Exception as e:
                print(f"An error occurred: {e}")
                self.active_users.remove(username)
                break
            else:
                client_socket.sendall("Login failed.".encode('utf-8'))
                client_socket.close()

        with self.lock:
            self.active_users.append(username)
        with self.lock:
            self.active_users.remove(username)

    def connect_server(self, username, password):
        """Connect to the server and authenticate"""
        try:
            if self.use_tls:
                self.client_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.host)

            self.client_socket.connect((self.host, self.port))

            # Send username and password to server
            print(f"Sending username: {username}, password: {password}")
            self.client_socket.sendall(username.encode('utf-8'))
            self.client_socket.sendall(password.encode('utf-8'))

            # Receive authentication response from server
            auth_response = self.client_socket.recv(1024).decode('utf-8')
            print(f"Server response: {auth_response}")
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

    def start_server(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Got connected from {addr}")
            
            #Wrap the client socket with TLS
            secure_client_socket = self.context.wrap_socket(client_socket, server_side=True)
            client_thread = threading.Thread(target=self.client_connect, args=(secure_client_socket,))
            client_thread.start()

if __name__ == "__main__":
    host = '0.0.0.0'
    port = 61626
    server = ServerSocket(host=host, port=port) 
    server.start_server()