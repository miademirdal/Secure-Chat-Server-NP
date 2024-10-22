import socket
import ssl
import threading

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
        self.context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    
    def ClientConnect(self, client_socket):
        print(f"Client Connected")
        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break;
                print(f"Received from client: {data.decode('utf-8')}")
                responseMessage = "Server: Message received!"
                client_socket.sendall(responseMessage.encode('utf-8'))
                    
                #client_socket, addr = self.server_socket.accept()
                
                #print(f"got connected on {addr}")
                #for message in messages:
                #    client_socket.send(message.encode('utf-8'))
                
            except Exception as e:
                print(f"An error occured: {e}")
                break
    
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
    server = ServerSocket(host=host, port=port)
    server.start_server()