import struct
import uuid
import socket
import os # צריך כדי לשמור את הפרתים בקובץ

#------2-------(הוספת ספריות הצפנה)-----
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from enum import Enum

class EResponseCode(Enum):
    Response_SUCCESS_REGISTRATION = 1600  # רישום הצליח
    Response_FAIL_REGISTRATION = 1601     # רישום נכשל
    Response_GET_SEND_PUBLIC_KEY = 1602   # התקבל מפתח ציבורי ושולח מפתח AES מוצפן
    Response_CRC_FILE_TRANSFER = 1603     # קובץ התקבל תקין CRC
    Response_CONF_MESSAGE = 1604          # מאושרת בקשת התחברות חוזרת
    Response_RECONNECT_CONF = 1605        # אישור התחברות חוזרת, שולח שוב את 1602
    Response_RECONNECT_IGNORE = 1606      # בקשה התחברות חוזרת נדחתה

#--------2END---------
HOST = '127.0.0.1'
PORT = 1256
file_path = 'port.info'
#getting the port
try:
    with open(file_path, 'r') as file:
        port = int(file.read().strip())
        print(f"Port from file: {port}")
        PORT = port
except FileNotFoundError:
    print(f"Warning: {file_path} not found. Using default port {PORT}.")
class Request:
    def __init__(self, client_id, version, code, payload_size, payload):
        self.client_id = client_id
        self.version = version
        self.code = code
        self.payload_size = payload_size
        self.payload = payload

def parse_request(data):
    client_id = data[:16].decode('utf-8').rstrip('\x00')
    version = struct.unpack('B', data[16:17])[0]
    code = struct.unpack('!H', data[18:20])[0]
    payload_size = struct.unpack('!I', data[20:24])[0]
    print(f"Client ID: {client_id}, Version: {version}, Code: {code}, Payload size: {payload_size}")
    payload = data[24:24+payload_size].decode('utf-8')
    print(f"Payload (UserName): {payload}")
    return Request(client_id, version, code, payload_size, payload)

#---------------------------------1--------------------------------
registered_users = set()


# Check if the user is registered and register if not
def check_and_register_user(username):
    if username in registered_users:
        return False, username  # User already exists
    else:
        registered_users.add(username)  # Register the user
        return True, username  # Successfully registered

def send_client_id(client_id, code=EResponseCode.Response_SUCCESS_REGISTRATION.value): #---(client_id,1600)
    version = 1
    payload = client_id.ljust(16, '\x00')
    payload_size = len(payload)
    header = struct.pack('!B H I', version, code, payload_size)
    response = header + payload.encode('utf-8')
    return response


# פונקציה לטיפול במפתח ציבורי מלקוח והצפנת מפתח AES
# פונקציה לשליחת מפתח AES מוצפן ללקוח
def send_encrypted_aes_key(username, public_key_pem):


    # יצירת מפתח AES חדש
    aes_key = get_random_bytes(32)  # מפתח AES בגודל 256 סיביות (32 בתים)

    # הצפנת מפתח ה-AES בעזרת המפתח הציבורי של הלקוח
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # בניית תשובת ההצפנה עם הקוד המתאים
    version = 1
    code = EResponseCode.Response_GET_SEND_PUBLIC_KEY.value  # קוד תשובה של מפתח AES מוצפן
    payload_size = len(encrypted_aes_key)
    header = struct.pack('!B H I', version, code, payload_size)
    response = header + encrypted_aes_key
    return response

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server is listening on port {PORT}...")
        ############----------------------3333----------------------------
        # Infinite loop waiting for client connections
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    print('Connected by', addr)
                    while True:

                        data = conn.recv(1024)

                        if not data:
                            break
                        req = parse_request(data)  # כל מה שמור שלחה לי
                        ##################################################################################
                        if req.code == 825:  # קוד בקשה עבור רישום
                            success, username = check_and_register_user(req.payload)  # בודק אם המשתמש כבר רשום
                            if success:
                                username = req.payload  # שם באורך 255 בתים
                                print(f"Registration request received with name: {username}")
                                client_id = str(uuid.uuid4())
                                response = send_client_id(client_id)
                                print(f"RESPONSE: {response}")
                                conn.sendall(response)  # שליחת התשובה ללקוח
                                print(f"Sent client ID: {client_id}  date: {response}")
                            else:
                                print(f"User {req.payload} already exists.")
                                response = send_client_id(username, code=1601)  # שליחת תשובת כשל (1601)
                                conn.sendall(response)  # החזרת תשובת כשל עם UUID

                        # טיפול במפתח ציבורי (קוד 826)
                        ##################################################################################
                        elif req.code == 826:  # קוד בקשה עבור מפתח ציבורי
                            username = req.client_id
                            public_key_pem = req.payload  # המפתח הציבורי נשלח כחלק מהמטען (payload)

                            # הצפנת מפתח AES בעזרת המפתח הציבורי ושליחת תשובה ללקוח
                            response = send_encrypted_aes_key(username, public_key_pem)
                            conn.sendall(response)
                            print(f"Sent AES key to {username}.")

                        ##################################################################################
                        elif req.code == 826:  # Public key exchange request code
                            username = req.client_id
                            public_key_pem = req.payload  # Public key is sent in the payload

                            # Encrypt AES key using the public key and send the response to the client
                            response = send_encrypted_aes_key(username, public_key_pem)
                            conn.sendall(response)
                            print(f"Sent AES key to {username}.")

                        ##################################################################################
                        # Handle reconnect request (code 827)
                        elif req.code == 827:  # קוד בקשה עבור התחברות חוזרת
                            username = req.payload.rstrip('\x00')  # Extract the username and remove the null terminator
                            print(f"Reconnect request received for user: {username}")

                            if username in registered_users:  # Check if the user is registered
                                print(f"User {username} exists. Reconnection confirmed.")

                                # Generate a new AES key (similar to code 1602 logic)
                                client_id = str(uuid.uuid4())[
                                            :16]  # Generate or use existing client ID, make sure it's 16 bytes
                                public_key_pem = req.payload  # You might need to retrieve the stored public key from memory
                                encrypted_aes_key = send_encrypted_aes_key(username,
                                                                           public_key_pem)  # Encrypt AES key using public key

                                # Send response for successful reconnection with AES key
                                response = struct.pack('!B H I', 1, 1605, len(encrypted_aes_key)) + client_id.encode(
                                    'utf-8').ljust(16, b'\x00') + encrypted_aes_key
                                conn.sendall(response)
                                print(f"Sent AES key and reconnection confirmation with client ID: {client_id}")

                            else:
                                print(f"User {username} not found. Reconnection denied.")

                                # Send failure response (reconnection denied) with code 1606
                                client_id = str(uuid.uuid4())[
                                            :16]  # Generate or reuse existing client ID, ensure it's 16 bytes
                                response = struct.pack('!B H I', 1, 1606, 16) + client_id.encode('utf-8').ljust(16,
                                                                                                                b'\x00')
                                conn.sendall(response)
                                print(f"Sent reconnection denial for user: {username}")


                        else:
                            print(f"Unknown request code: {client_id}")
                            conn.sendall(b"Unknown request")
            except KeyboardInterrupt:
                print("Server shutting down.")
                break
            except Exception as e:
                print(f"Unexpected error occurred: {e}")




