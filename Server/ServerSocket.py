import socket

class ServerSocket:
    """server class"""
    
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def start_server(self):
        print("Starting Server...")
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(2)
        
            print(f"server connected on {self.host}:{self.port}")
        
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"got connected on {addr}")
            
                messages = [
                    "Server: Hello~~",
                    "Server: What's up",
                    "Server: Your chat program works well~",
                    "Server: Ok. Have fun!"
                ]

                for message in messages:
                    client_socket.send(message.encode('utf-8'))
                    data = client_socket.recv(1024)
                
                if data:
                    print(f"Received from client: {data.decode('utf-8')}")

        except Exception as e:
            print(f"An error occured: {e}")

        finally:
            client_socket.close()
    
if __name__ == "__main__":
    host = '127.0.0.1'
    port = 1200
    server = ServerSocket(host=host, port=port)
    server.start_server()