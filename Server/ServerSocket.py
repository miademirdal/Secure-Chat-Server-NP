import socket
import ssl
import threading
from pymongo import MongoClient
import bcrypt

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
        self.context.load_cert_chain(certfile='server.crt', keyfile='server.key') #error on this line
        
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
        
        username = client_socket.recv(1024).decode('utf-8')
        password = client_socket.recv(1024).decode('utf-8')
        
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
                    
                #client_socket, addr = self.server_socket.accept()
                
                #print(f"got connected on {addr}")
                #for message in messages:
                #    client_socket.send(message.encode('utf-8'))
                
                except Exception as e:
                    print(f"An error occurred: {e}")
                    break
        else:
            print(f"User {username} could not be authenticated.")
            client_socket.close()
    
    def start_server(self):
        print("Starting Server...")
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Got connected from {addr}")
            
            #Wrap the client socket with TLS
            secure_client_socket = self.context.wrap_socket(client_socket, server_side=True)
            client_thread = threading.Thread(target=self.handle_client, args=(secure_client_socket,))
            client_thread.start()
            
if __name__ == "__main__":
    host = '127.0.0.1'
    port = 1200
    server = ServerSocket(host=host, port=port) #error on this line
    server.start_server()