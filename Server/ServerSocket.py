import socket
import ssl
import threading
from pymongo import MongoClient
import bcrypt
import tkinter as tk

class ServerSocket:
    """server class"""
    
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server started on {self.host}:{self.port}")
        
        #ssl content
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile='Server/server.crt', keyfile='Server/localhost.key')
        
        #setup MongoDB
        self.client_db = MongoClient("mongodb://localhost:27017/")
        self.db = self.client_db['chat_db']
        self.user_collection = self.db['users']
        
    def user_storage(self, username: str, password: str):
        #storing the usernames and passwords in MongoDB
        if not self.user_collection.find_one({"username" : username}):
            hashed_password =bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            self.user_collection.insert_one({"username" : username, "password" : hashed_password})
            print(f"Stored user: {username}")
        else:
            print(f"Username {username} is already in use.")
            
    def user_auth(self, username: str, password: str):
        user = self.user_collection.find_one({"username" : username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return True
        return False
    
    def client_connect(self, client_socket):
        print(f"Client Connected")
    
        # Receive the username and password
        username = client_socket.recv(1024).decode('utf-8')
        password = client_socket.recv(1024).decode('utf-8')
    
        print(f"Received username: {username}")
        print(f"Received password: {password}")

        # Authenticate the user
        if self.user_auth(username, password):
            print(f"You are logged in! {username}")
            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    print(f"Received from client: {data.decode('utf-8')}")
                    responseMessage = "Server: Message received!"
                    client_socket.sendall(responseMessage.encode('utf-8'))
                except Exception as e:
                    print(f"An error occurred: {e}")
                    break
        else:
            print(f"User {username} could not be authenticated.")
            client_socket.sendall("Authentication failed.".encode('utf-8'))
            client_socket.close()
            
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
    host = 'localhost'
    port = 1200
    server = ServerSocket(host=host, port=port) 
    server.start_server()