import struct
import uuid
import socket
import base64
from Crypto.Util.Padding import pad, unpad
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from enum import Enum
from cksum import memcrc
from Crypto.Cipher import AES
import cksum
#from concurrent.futures import ThreadPoolExecutor
import threading

def get_bits(input_string, num_bits):
    binary_data = ''.join(format(ord(char), '08b') for char in input_string)
    return binary_data[:num_bits]


class EResponseCode(Enum):
    Response_SUCCESS_REGISTRATION = 1600  # רישום הצליח
    Response_FAIL_REGISTRATION = 1601  # רישום נכשל
    Response_GET_SEND_PUBLIC_KEY = 1602  # התקבל מפתח ציבורי ושולח מפתח AES מוצפן
    Response_CRC_FILE_TRANSFER = 1603  # קובץ התקבל תקין CRC
    Response_CONF_MESSAGE = 1604  # מאושרת בקשת התחברות חוזרת
    Response_RECONNECT_CONF = 1605  # אישור התחברות חוזרת, שולח שוב את 1602
    Response_RECONNECT_IGNORE = 1606  # בקשה התחברות חוזרת נדחתה


HOST = '127.0.0.1'
PORT = 1256
file_path = 'port.info'
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
    client_id = data[:16]  # .decode('utf-8').rstrip('\x00')
    version = struct.unpack('B', data[16:17])[0]
    code = struct.unpack('!H', data[18:20])[0]
    payload_size = struct.unpack('!I', data[20:24])[0]
    if code != 828:
        payload = data[24:24 + payload_size].decode('utf-8')
    else:
        payload = data[24:24 + payload_size]
    print(f"Client ID: {client_id}, Version: {version}, Code: {code}, Payload size: {payload_size} Payload: {payload}")
    return Request(client_id, version, code, payload_size, payload)


# ---------------------------------1--------------------------------
registered_users = set()


# Check if the user is registered in the file and register if not
def check_and_register_user_in_file(username):
    users = {}
    if os.path.exists('registed_name_uuid.txt'):
        with open('registed_name_uuid.txt', 'r') as file:
            for line in file:
                stored_username, stored_uuid, stored_aes_key = line.strip().split(',')
                users[stored_username] = (stored_uuid, stored_aes_key)

    if username in users:
        return False, users[username][0], users[username][1]  # User already exists
    else:
        new_uuid = (uuid.uuid4())  # Generate new UUID
        uuid_16_bytes = new_uuid.bytes
        aes_key = base64.b64encode(get_random_bytes(32)).decode('ascii')  # Generate AES key
        users[username] = (uuid_16_bytes, aes_key)
        # Write the new user data to the file
        with open('registed_name_uuid.txt', 'a') as file:
            file.write(f"{username},{new_uuid},{aes_key}\n")

        return True, new_uuid, aes_key  # Successfully registered


def send_client_id(client_id, code=EResponseCode.Response_SUCCESS_REGISTRATION.value):  # ---(client_id,1600)
    version = 1
    payload = client_id.bytes  # .ljust(16, '\x00')
    payload_size = len(payload)
    header = struct.pack('!B H I', version, code, payload_size)
    response = header + payload  # .encode('utf-8')
    return response

#b"\xaf\xe7\x1av\xdc\x9bF\xc6\x8a0\xe9'\x9b\x92\xc1e"
#b214c633-82fa-4c5c-8a79-c79c4edaea11
# פונקציה לטיפול במפתח ציבורי מלקוח והצפנת מפתח AES
# פונקציה לטיפול במפתח ציבורי מלקוח והצפנת מפתח AES
def send_encrypted_aes_key(username, public_key):
    try:
        aes_key_base64 = load_aes_key()  # get_random_bytes(32)
        aes_key = base64.b64decode(aes_key_base64)
        public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
        public_key = RSA.import_key(public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        # בניית תשובת ההצפנה עם הקוד המתאים
        version = 1
        code = EResponseCode.Response_GET_SEND_PUBLIC_KEY.value
        clientId = load_clientId_by_name_key_from_file(username)
        clientI16 = clientId.bytes

        payload = clientI16 + encrypted_aes_key
        payload_size = len(payload)
        header = struct.pack('!B H I', version, code, payload_size)
        response = header + payload
        return response
    except Exception as e:
        print(f"Error in send_encrypted_aes_key: {e}")
        return None



# ------------------------for 826----------------------------------------
# Load AES keys from the registration file
def load_clientId_by_name_key_from_file(userNAme):
    if os.path.exists('registed_name_uuid.txt'):
        with open('registed_name_uuid.txt', 'r') as file:
            for line in file:
                stored_username, stored_client_id, stored_aes_key = line.strip().split(',')
                if stored_username == userNAme:
                    return uuid.UUID(stored_client_id)  # Decode the stored AES key
    return None  # Return None if no matching client ID is found


# ------------------------for 828----------------------------------------
# Load AES keys from the registration file
def load_aes_key():
    """Loads the AES key for the given client ID from the 'registed_name_uuid.txt' file."""
    if os.path.exists('registed_name_uuid.txt'):
        with open('registed_name_uuid.txt', 'r') as file:
            for line in file:
                stored_username, stored_client_id, stored_aes_key = line.strip().split(',')
                return stored_aes_key  # base64.b64decode(stored_aes_key)  # Decode the stored AES key
    return None  # Return None if no matching client ID is found


# ------------------------for 828-- Load AES keys from the registration file
def load_aes_key_from_file(client_id):
    """Loads the AES key for the given client ID from the 'registed_name_uuid.txt' file."""
    if os.path.exists('registed_name_uuid.txt'):
        with open('registed_name_uuid.txt', 'r') as file:
            for line in file:
                stored_username, stored_client_id, stored_aes_key = line.strip().split(',')
                if stored_client_id == client_id:
                    return base64.b64decode(stored_aes_key)  # Decode the stored AES key
    return None  # Return None if no matching client ID is found---------------and for 828---------------------------------------------

############################################################
def handle_client(conn, addr):
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            req = parse_request(data)  # כל מה שמור שלחה לי

            #############################825 -->1600####################################
            if req.code == 825:  # קוד בקשה עבור רישום
                success, client_id, aes_key = check_and_register_user_in_file(req.payload)
                if success:
                    print("IM HERE 1")
                    username = req.payload  # שם באורך 255 בתים
                    response = send_client_id(client_id)
                    conn.sendall(response)  # שליחת התשובה ללקוח
                    print(f"Sent client ID: {client_id}  date: {response}")
                else:
                    print(f"User {req.payload} already exists.")
                    response = send_client_id(client_id, code=1601)
                    conn.sendall(response)

            ################################  טיפול במפתח ציבורי 826 -->1602 #####################################
            elif req.code == 826:
                print("IM HERE 2")
                payloadSplited = req.payload.split('\0')
                username = payloadSplited[0]
                public_key_pem = payloadSplited[1]
                # הצפנת מפתח AES בעזרת המפתח הציבורי ושליחת תשובה
                response = send_encrypted_aes_key(username, public_key_pem)
                conn.sendall(response)
                print(f"Sent AES key to {username}.")

            ############################ 828 Handle file transfer request ################
            elif req.code == 828:
                print("IM HERE 3")
                # Extract Size Content (4 bytes) - Encrypted file
                size_content = struct.unpack('!I', data[24:28])[0]
                # Extract Size File Orig (4 bytes) - Original file
                size_file_orig = struct.unpack('!I', data[28:32])[0]
                # Extract Packet Number and Total Packets (4 bytes)
                packet_number, total_packets = struct.unpack('!HH', data[32:36])
                # Extract the File Name (255 bytes, null-terminated)
                file_name1 = data[36:291]
                file_name = file_name1.split(b'\x00', 1)[0]  # Only take the first part before the padding
                content_message = data[291:291 + size_content]
                # Saving the encrypted file to disk
                encrypted_file_path = f"client_files/received_{req.client_id}_{file_name}"
                encrypted_file_path = f"file.txt"
                with open(encrypted_file_path, 'wb') as f:
                    f.write(content_message)
                aes_key_base64 = load_aes_key()  # load_aes_key_from_file(req.client_id)
                aes_key = base64.b64decode(aes_key_base64)
                if not aes_key:
                    raise ValueError(f"No AES key found for client {req.client_id}. Cannot decrypt the file.")
                else:
                    iv = b'\x00' * 16
                    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    decrypted_content = cipher.decrypt(content_message)

                    # Save the decrypted file
                    decrypted_content_copy = decrypted_content[:size_file_orig]
                    with open("fileee.txt", 'wb') as f:
                        f.write(decrypted_content_copy)

                    # Calculate the CRC checksum using cksum's memcrc
                    crc_value = memcrc(decrypted_content[:size_file_orig])  # Use memcrc from cksum.py for the CRC calculation

                    print(f"CRC Checksum: {crc_value:#010x}")

                    # Build the response message (code 1603)
                    client_id = uuid.uuid4().bytes
                    size_content_bytes = struct.pack('!I', size_content)  # Size Content (4 bytes)
                    file_name_bytes = file_name.ljust(255, b'\x00')  # File Name (255 bytes)
                    crc_bytes = struct.pack('!I', crc_value)  # CRC (4 bytes)

                    # Construct the complete response
                    response_code = EResponseCode.Response_CRC_FILE_TRANSFER.value  # Use 1603 for CRC confirmation
                    response = struct.pack('!B H I', 1, response_code, 16 + 4 + 255 + 4)  # Header with payload size
                    response += client_id + size_content_bytes + file_name_bytes + crc_bytes

                    # Send the response back to the client
                    conn.sendall(response)
                    print(f"Sent CRC  response to the client with ID: {req.client_id}")

            # טיפולים בקודים 900-902
            elif req.code == 900:
                client_id = uuid.uuid4().bytes
                response_code = EResponseCode.Response_CONF_MESSAGE.value
                response = struct.pack('!B H I', 1, response_code, 16)  # Header with payload size
                response += client_id
                conn.sendall(response)
                print(f"Sent confirmation response to the client with ID: {req.client_id}")

            elif req.code == 901 or req.code == 902:
                file_name = req.payload.rstrip('\x00')
                client_id = uuid.uuid4().bytes
                response_code = EResponseCode.Response_CONF_MESSAGE.value
                response = struct.pack('!B H I', 1, response_code, 16)  # Header with payload size
                response += client_id
                conn.sendall(response)
                print(f"not correct {file_name} send again CRC")

            else:
                print(f"Unknown request code: {req.code}")
                conn.sendall(b"Unknown request")

        print(f"Closing connection with {addr}")


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server is listening on port {PORT}...")

        while True:
            try:
                conn, addr = s.accept()
                print(f"Connected by {addr}")
                # יצירת תהליכון חדש עבור כל לקוח
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()
            except KeyboardInterrupt:
                print("Server shutting down.")
                break
            except Exception as e:
                print(f"Unexpected error occurred: {e}")
