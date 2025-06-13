import socket
import threading
from app.security import Encryption
from app.storage import LogManager

class Server:
    def __init__(self, host="0.0.0.0", port=12346):  # Ubah port ke 12346
        self.host = host
        self.port = port
        # ... kode lainnya tetap sama   

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"[SERVER] Listening on {self.host}:{self.port}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"[SERVER] Connection from {addr}")
            self.clients.append(client_socket)
            threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True).start()

    def handle_client(self, client_socket, addr):
        while True:
            try:
                encrypted_message = client_socket.recv(4096)
                if not encrypted_message:
                    break
                message = self.encryption.decrypt(encrypted_message)
                print(f"[RECEIVED] {addr}: {message}")
                self.logger.add_log(f"Received from {addr}: {message}")
                for client in self.clients:
                    if client != client_socket:
                        client.send(self.encryption.encrypt(message))
            except Exception as e:
                print(f"[ERROR] {e}")
                break
        client_socket.close()
        self.clients.remove(client_socket)
        print(f"[SERVER] Disconnected {addr}")

class NetworkScanner:
    def scan_network(self):
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return None