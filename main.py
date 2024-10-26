from client_handler import handle_client
import socket
import threading

HOST = '127.0.0.1'
DEFAULT_PORT = 1256
FILE_PATH = 'port.info'


def get_port():
    """Reads the port from a file or returns a default port if the file is missing."""
    try:
        with open(FILE_PATH, 'r') as file:
            port = int(file.read().strip())
            print(f"Port from file: {port}")
            return port
    except FileNotFoundError:
        print(f"Warning: {FILE_PATH} not found. Using default port {DEFAULT_PORT}.")
        return DEFAULT_PORT


def start_server():
    """Initializes and starts the server, listening for client connections."""
    port = get_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen()
        print(f"Server is listening on port {port}...")

        try:
            while True:
                conn, addr = s.accept()
                print(f"Connected by {addr}")
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()
        except KeyboardInterrupt:
            print("Server shutting down.")
        except Exception as e:
            print(f"Unexpected error occurred: {e}")


if __name__ == "__main__":
    start_server()
