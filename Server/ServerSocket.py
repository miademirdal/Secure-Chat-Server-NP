import socket
import ssl
import threading
from pymongo import MongoClient
import bcrypt
from threading import Lock

class CentralServerSocket:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

        # Socket setup
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(10)
        print(f"Server started on {self.host}:{self.port}")

        # SSL setup
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile='Server/server.crt', keyfile='Server/server.key')

        # MongoDB setup
        self.client_db = MongoClient("mongodb://clinet.ddns.net:27017/")
        self.db = self.client_db['chat_db']
        self.user_collection = self.db['users']

        # Threading utilities
        self.lock = Lock()
        self.active_users = {}  # Map of usernames to client sockets
        self.connected_clients = []  # List of client sockets

    def start_server(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection received from {addr}")
            # Secure the client socket
            secure_client_socket = self.context.wrap_socket(client_socket, server_side=True)
            # Handle client connection in a new thread
            threading.Thread(target=self.client_connect, args=(secure_client_socket,), daemon=True).start()

    def client_connect(self, client_socket):
        try:
            action = client_socket.recv(1024).decode('utf-8')
            if action == "register":
                self.handle_registration(client_socket)
            elif action == "login":
                self.handle_login(client_socket)
        except ssl.SSLError as e:
            print(f"SSL error: {e}")
        except Exception as e:
            print(f"Error handling client: {e}")
       

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
                self.active_users[username] = client_socket
                self.connected_clients.append(client_socket)
            self.update_active_users()
            threading.Thread(target=self.handle_chat, args=(client_socket, username), daemon=True).start()
        else:
            client_socket.sendall("Login failed.".encode('utf-8'))

    def handle_chat(self, client_socket, username):
        try:
            while True:
                message = client_socket.recv(1024).decode('utf-8')
                if message.lower() == 'end':
                    break
                print(f"{username}: {message}")
                self.broadcast_message(f"{username}: {message}", exclude_socket=client_socket)
        except Exception as e:
            print(f"Connection lost with {username}: {e}")
        finally:
            self.remove_user(username, client_socket)

    def broadcast_message(self, message, exclude_socket=None):
        with self.lock:
            for client in self.connected_clients:
                if client != exclude_socket:
                    try:
                        client.sendall(message.encode('utf-8'))
                    except (socket.error, ssl.SSLError) as e:
                        print(f"Error sending message: {e}")
                        self.remove_client(client)

    def user_storage(self, username: str, password: str) -> bool:
        if self.user_collection.find_one({"username": username}):
            return False  # Username already exists
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.user_collection.insert_one({"username": username, "password": hashed_password})
        print(f"Stored user: {username}")
        return True

    def user_auth(self, username: str, password: str) -> bool:
        user = self.user_collection.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return True
        return False

    def update_active_users(self):
        active_users_list = ', '.join(self.active_users.keys())
        for client in self.connected_clients:
            try:
                client.sendall(f"Active Users: {active_users_list}".encode('utf-8'))
            except:
                print("Failed to update active users list.")

    def remove_user(self, username, client_socket):
        with self.lock:
            if username in self.active_users:
                del self.active_users[username]
            if client_socket in self.connected_clients:
                self.connected_clients.remove(client_socket)
        try:
            client_socket.close()
        except:
            pass
        self.update_active_users()
        print(f"User {username} disconnected.")

if __name__ == "__main__":
    host = 'clinet.ddns.net'
    port = 61626
    server = CentralServerSocket(host=host, port=port)
    server.start_server()
