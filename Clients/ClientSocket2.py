import socket

class ClientSocket:
    """Client class"""
    
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect_server(self):
        try:
            self.client_socket.connect((self.host, self.port))
            print(f"Server connected on {self.host}:{self.port} \n Hello welcome to this chat server!")

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