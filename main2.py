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
import threading

from threading import Lock

# יצירת מנעול לשימוש בפונקציות הקוראות והכותבות לקובץ
file_lock = Lock()
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
    print(f"in mddle Client ID: {client_id}, Version: {version}, Code: {code}")
    payload_size = struct.unpack('!I', data[20:24])[0]
    if code != 828:
        payload = data[24:24 + payload_size].decode('utf-8')
    else:
        payload = data[24:24 + payload_size]
    print(f"Client ID: {client_id}, Version: {version}, Code: {code}, Payload size: {payload_size}")
    return Request(client_id, version, code, payload_size, payload)


# ---------------------------------1--------------------------------
registered_users = set()


# Check if the user is registered in the file and register if not
def check_and_register_user_in_file(username):
    with file_lock:  # כניסה לנעילה בעת עבודה עם הקובץ
        users = {}
        if os.path.exists('registed_name_uuid.txt'):
            with open('registed_name_uuid.txt', 'r') as file:
                for line in file:
                    stored_username, stored_uuid, *_ = line.strip().split(',')
                    users[stored_username] = (stored_uuid)

        if username in users:
            return False, users[username][0], users[username][1]  # User already exists
        else:
            new_uuid = (uuid.uuid4())  # Generate new UUID
            uuid_16_bytes = new_uuid.bytes
            users[username] = (uuid_16_bytes)
            # Write the new user data to the file
            with open('registed_name_uuid.txt', 'a') as file:
                file.write(f"{username},{new_uuid}\n")
            return True, new_uuid  # Successfully registered


def save_publick_and_aes_key(user_name, aes_key, public_key):
    end_marker = "#END#"
    with file_lock:  # כניסה לנעילה בעת עבודה עם הקובץ
        if os.path.exists('registed_name_uuid.txt'):
            with open('registed_name_uuid.txt', 'r') as file:
                lines = file.readlines()
            with open('registed_name_uuid.txt', 'w') as file:
                for i, line in enumerate(lines):
                    username, id_client, *_ = line.strip().split(',')
                    if user_name == username:
                        lines[i] = f"{username},{id_client},{aes_key},{public_key}{end_marker}"
                        break;
                file.writelines(lines)


def send_client_id(client_id, code=EResponseCode.Response_SUCCESS_REGISTRATION.value):  # ---(client_id,1600)
    version = 1
    payload = client_id.bytes  # .ljust(16, '\x00')
    payload_size = len(payload)
    header = struct.pack('!B H I', version, code, payload_size)
    response = header + payload  # .encode('utf-8')
    return response


# פונקציה לטיפול במפתח ציבורי מלקוח והצפנת מפתח AES
def send_encrypted_aes_key(username, public_key, code):
    aes_key_base64 = base64.b64encode(get_random_bytes(32)).decode('ascii')
    save_publick_and_aes_key(username, aes_key_base64, public_key)
    # aes_key_base64 = load_aes_by_name(username)
    aes_key = base64.b64decode(aes_key_base64)
    public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    # בניית תשובת ההצפנה עם הקוד המתאים
    version = 1
    client_id_str = load_client_id(username)
    client_id = uuid.UUID(client_id_str)
    clientI16 = client_id.bytes
    # save_publick_and_aes_key(username,aes_key,public_key)
    payload = clientI16 + encrypted_aes_key
    payload_size = len(payload)
    header = struct.pack('!B H I', version, code, payload_size)
    response = header + payload
    return response


def load_public_key(user_name):
    end_marker = "#END#"
    with open('registed_name_uuid.txt', 'r') as file:
        content = file.read()
    records = content.split(end_marker)
    for record in records:
        name, id, aes, public = record.split(',')
        if name == user_name:
            return public
    return None


def load_client_id(user_name):
    end_marker = "#END#"
    with open('registed_name_uuid.txt', 'r') as file:
        content = file.read()
    records = content.split(end_marker)
    for record in records:
        name, id, *_ = record.split(',')
        if name == user_name:
            return id
    return None


def load_aes_by_id(clientid):
    end_marker = "#END#"
    with open('registed_name_uuid.txt', 'r') as file:
        content = file.read()
    records = content.split(end_marker)
    for record in records:
        name, id, aes, *_ = record.split(',')
        u = uuid.UUID(id)
        uuid_bytes = u.bytes;
        if clientid == uuid_bytes:
            return aes
    return None


def load_aes_by_name(username):
    end_marker = "#END#"
    with open('registed_name_uuid.txt', 'r') as file:
        content = file.read()
    records = content.split(end_marker)
    for record in records:
        name, id, aes, *_ = record.split(',')
        if username == name:
            return aes
    return None


def handle_client(conn, addr):
    with conn:
        print('Connected by', addr)
        # Infinite loop waiting for client connections
        while True:
                data = conn.recv(8192)
                if not data:
                    break
                req = parse_request(data)
                #############################825 -->1600####################################
                if req.code == 825:  # קוד בקשה עבור רישום
                    success, client_id = check_and_register_user_in_file(req.payload)
                    if success:
                        username = req.payload  # שם באורך 255 בתים
                        response = send_client_id(client_id)
                        conn.sendall(response)  # שליחת התשובה ללקוח
                        print(f"Sent client ID: {client_id}  date: {response}")
                    #############################825 -->#1601####################################
                    else:
                        print(f"User {req.payload} already exists.")
                        response = send_client_id(client_id, code=1601)
                        conn.sendall(response)

                ################################  טיפול במפתח ציבורי 826 -->1602 #####################################
                elif req.code == 826:
                    payloadSplited = req.payload.split('\0')
                    username = payloadSplited[0]
                    public_key_pem = payloadSplited[1]
                    response = send_encrypted_aes_key(username, public_key_pem,EResponseCode.Response_GET_SEND_PUBLIC_KEY.value)
                    conn.sendall(response)
                    print(f"Sent AES key to {username}.")
                elif req.code == 828:
                            size_content = struct.unpack('!I', data[24:28])[0]
                            size_file_orig = struct.unpack('!I', data[28:32])[0]
                            packet_number, total_packets = struct.unpack('!HH', data[32:36])
                            file_name1 = data[36:291]
                            file_name = file_name1.split(b'\x00', 1)[0]  # Only take the first part before the padding
                            content_message = data[291:291 + size_content]
                            encrypted_file_path = f"{username}file.txt"
                            if packet_number==1:
                                with open(encrypted_file_path, 'wb') as file:
                                    file.write(content_message)
                            else:
                                with open(encrypted_file_path, 'ab') as f:  # 'ab' = append in binary mode
                                    f.write(content_message)
                            if packet_number==total_packets:
                                with open(f'{username}file.txt', 'rb') as file:
                                     file_content = file.read()  # קריאת תוכן הקובץ כולו
                                aes_key_base64 =load_aes_by_id(req.client_id) #load_aes_key_from_file(req.client_id)
                                aes_key = base64.b64decode(aes_key_base64)
                                if not aes_key:
                                    raise ValueError(f"No AES key found for client {req.client_id}. Cannot decrypt the file.")
                                else:
                                    iv = b'\x00' * 16
                                    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                                    decrypted_content = cipher.decrypt(file_content)
                                    print(f"Decrypted file content saved")
                                    decrypted_content_copy = decrypted_content[:size_file_orig]
                                    with open(f"{username}decrypted_file.txt", 'wb') as f:
                                        f.write(decrypted_content_copy)
                                crc_value = memcrc(decrypted_content[:size_file_orig])  # Use memcrc from cksum.py for the CRC calculation
                                print(f"CRC Checksum: {crc_value:#010x}")
                                client_id = uuid.uuid4().bytes
                                size_content_bytes = struct.pack('!I', size_content)  # Size Content (4 bytes)
                                file_name_bytes = file_name.ljust(255, b'\x00') # File Name (255 bytes)
                                crc_bytes = struct.pack('!I', crc_value)  # CRC (4 bytes)
                                response_code = EResponseCode.Response_CRC_FILE_TRANSFER.value  # Use 1603 for CRC confirmation
                                response = struct.pack('!B H I', 1, response_code, 16 + 4 + 255 + 4)  # Header with payload size
                                response += client_id + size_content_bytes + file_name_bytes + crc_bytes
                                conn.sendall(response)
                                print(f"Sent CRC  response to the client with ID: {req.client_id}")
                elif req.code == 900:
                    client_id = uuid.uuid4().bytes
                    response_code = EResponseCode.Response_CONF_MESSAGE.value
                    response = struct.pack('!B H I', 1, response_code, 16)  # Header with payload size
                    response += client_id
                    conn.sendall(response)

                    print(f"Sent confirmation response to the client with ID: {req.client_id}")
                elif req.code == 901:
                    file_name = req.payload.rstrip('\x00')
                    # retry_counts[file_name] = retry_counts.get(file_name, 0) + 1
                    client_id = uuid.uuid4().bytes
                    response_code = EResponseCode.Response_CONF_MESSAGE.value
                    response = struct.pack('!B H I', 1, response_code, 16)  # Header with payload size
                    response += client_id
                    conn.sendall(response)
                    print(f"not correct {file_name} send gaain CRC ")
                elif req.code == 902:
                    file_name = req.payload.rstrip('\x00')
                    # retry_counts[file_name] = retry_counts.get(file_name, 0) + 1
                    client_id = uuid.uuid4().bytes
                    response_code = EResponseCode.Response_CONF_MESSAGE.value
                    response = struct.pack('!B H I', 1, response_code, 16)  # Header with payload size
                    response += client_id
                    conn.sendall(response)
                    print(f"not correct {file_name} send gaain CRC ")
                elif req.code == 827:  # קוד בקשה עבור התחברות חוזרת
                    username = req.payload.rstrip('\x00')
                    public_key = load_public_key(username)
                    if public_key != None:
                        print(f"User {username} exists. Reconnection confirmed.")
                        response = send_encrypted_aes_key(username, public_key,
                                                          EResponseCode.Response_RECONNECT_CONF.value)
                        conn.sendall(response)
                        print(f"Sent AES key and reconnection confirmation with user name {username}")
                    else:
                        print(f"User {username} not found. Reconnection denied.")
                        client_id = uuid.uuid4().bytes
                        response = struct.pack('!B H I', 1, EResponseCode.Response_RECONNECT_IGNORE.value, 16)
                        response += client_id
                        conn.sendall(response)
                        print(f"Sent reconnection denial for user: {username}")
                else:
                    print(f"Unknown request code: {client_id}")
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