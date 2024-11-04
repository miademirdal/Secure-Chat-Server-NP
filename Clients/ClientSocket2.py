import socket
import ssl
import threading

class ClientSocket2:
    """Client class"""
    
    def __init__(self, host: str, port: int, use_tls: bool = False) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_tls:
            self.context = ssl.create_default_context()
   
    def recive_messages(self):
        while True:
            try:
                response = self.client_socket.recv(1024)
                if not response:
                    print("Server has closed the connection.")
                    break
                print(f"Recived from server: {response.decode('utf-8')}")
            except Exception as e:
                print(f"An error occurred while receiving a message: {e}")
                break
    
    def connect_server(self):
        try:
            self.client_socket.connect((self.host, self.port))
            print(f"Server connected {'with TLS' if self.use_tls else 'without TLS'} on {self.host}:{self.port} \nHello, welcome to this chat server!")

            if self.use_tls:
                self.client_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.host)
           
            username = input("Enter your Username: ")
            password = input("Enter your Password: ")


            self.client_socket.sendall(username.encode('utf-8'))
            self.client_socket.sendall(username.encode('utf-8'))

            threading.Thread(target=self.recive_messages, daemon=True).start()

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
    use_tls = True
    client = ClientSocket2(host=host, port=port)
    client.connect_server()