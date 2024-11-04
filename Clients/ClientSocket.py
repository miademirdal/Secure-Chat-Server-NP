import socket
import ssl
import threading

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
                print(f"Received from server: {response.decode('utf-8')}")
            except Exception as e:
                print(f"An error occurred while receiving a message: {e}")
                break
            
    def connect_server(self):
        try:
            if self.use_tls:
                self.client_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.host)

            self.client_socket.connect((self.host, self.port))
            print(f"Server connected with {'TLS' if self.use_tls else 'no TLS'} on {self.host}:{self.port} \nHello, welcome to this chat server!")
            
            username = input("Enter your username: ")
            password = input("Enter your password: ")

            self.client_socket.sendall(username.encode('utf-8'))
            self.client_socket.sendall(password.encode('utf-8'))
            
            threading.Thread(target=self.receive_messages, daemon=True).start()

            while True:
                message_to_send = input("Enter message to send (type 'end' to quit): ")

                if message_to_send.lower() == 'end':
                    print("Ending connection.")
                    self.client_socket.sendall(message_to_send.encode('utf-8'))
                    break

                self.client_socket.sendall(message_to_send.encode('utf-8'))

                response = self.client_socket.recv(1024)
                print(f"Received from server: {response.decode('utf-8')}")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.client_socket.close()
        
if __name__ == "__main__":
    host = '127.0.0.1'
    port = 1200
    client = ClientSocket(host=host, port=port)
    client.connect_server()