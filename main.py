import struct
import uuid
import socket
import base64
import os  # צריך כדי לשמור את הפרתים בקובץ

# ------2-------(הוספת ספריות הצפנה)-----
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from enum import Enum
from cksum import memcrc  # Import the CRC calculation function from cksum.py
from Crypto.Cipher import AES #for 828 !!!!!we have 2 of this need one!!!!!!!!!!!!


import cksum  # Import custom CRC checksum calculation from cksum.py
class EResponseCode(Enum):
    Response_SUCCESS_REGISTRATION = 1600  # רישום הצליח
    Response_FAIL_REGISTRATION = 1601  # רישום נכשל
    Response_GET_SEND_PUBLIC_KEY = 1602  # התקבל מפתח ציבורי ושולח מפתח AES מוצפן
    Response_CRC_FILE_TRANSFER = 1603  # קובץ התקבל תקין CRC
    Response_CONF_MESSAGE = 1604  # מאושרת בקשת התחברות חוזרת
    Response_RECONNECT_CONF = 1605  # אישור התחברות חוזרת, שולח שוב את 1602
    Response_RECONNECT_IGNORE = 1606  # בקשה התחברות חוזרת נדחתה


# --------2END---------
HOST = '127.0.0.1'
PORT = 1256
file_path = 'port.info'
# getting the port
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
    payload = data[24:24 + payload_size].decode('utf-8')
    print(f"Payload (UserName): {payload}")
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
        new_uuid = str(uuid.uuid4())  # Generate new UUID
        aes_key = base64.b64encode(get_random_bytes(32)).decode('ascii')  # Generate AES key
        users[username] = (new_uuid, aes_key)

        # Write the new user data to the file
        with open('registed_name_uuid.txt', 'a') as file:
            file.write(f"{username},{new_uuid},{aes_key}\n")

        return True, new_uuid, aes_key  # Successfully registered
# Check if the user is registered and register if not
# def check_and_register_user(username):
#     if username in registered_users:
#         return False, username  # User already exists
#     else:
#         registered_users.add(username)  # Register the user
#         return True, username  # Successfully registered


def send_client_id(client_id, code=EResponseCode.Response_SUCCESS_REGISTRATION.value):  # ---(client_id,1600)
    version = 1
    payload = client_id.ljust(16, '\x00')
    payload_size = len(payload)
    header = struct.pack('!B H I', version, code, payload_size)
    response = header + payload.encode('utf-8')
    return response


# פונקציה לטיפול במפתח ציבורי מלקוח והצפנת מפתח AES
# פונקציה לשליחת מפתח AES מוצפן ללקוח
def send_encrypted_aes_key(username, public_key):
    # יצירת מפתח AES אקראי (32 בתים עבור AES-256)
    aes_key = get_random_bytes(32)
    public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    result_encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('ascii')

    # בניית תשובת ההצפנה עם הקוד המתאים
    version = 1
    code = EResponseCode.Response_GET_SEND_PUBLIC_KEY.value  # קוד תשובה של מפתח AES מוצפן
    payload_size = len(result_encrypted_aes_key)
    header = struct.pack('!B H I', version, code, payload_size)
    encrypted_aes_key_bytes = base64.b64decode(result_encrypted_aes_key)
    response = header + encrypted_aes_key_bytes
    return response

#------------------------for 828----------------------------------------
# Load AES keys from the registration file
def load_aes_key_from_file(client_id):
    """Loads the AES key for the given client ID from the 'registed_name_uuid.txt' file."""
    if os.path.exists('registed_name_uuid.txt'):
        with open('registed_name_uuid.txt', 'r') as file:
            for line in file:
                stored_username, stored_client_id, stored_aes_key = line.strip().split(',')
                if stored_client_id == client_id:
                    return base64.b64decode(stored_aes_key)  # Decode the stored AES key
    return None  # Return None if no matching client ID is found
#---------------and for 828---------------------------------------------

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
                        #############################825 --> 1600####################################
                        if req.code == 825:  # קוד בקשה עבור רישום
                            success, client_id, aes_key = check_and_register_user_in_file(req.payload)
                            if success:
                                username = req.payload  # שם באורך 255 בתים
                                print(f"Registration request received with name: {username}")
                                response = send_client_id(client_id)
                                print(f"RESPONSE: {response}")
                                conn.sendall(response)  # שליחת התשובה ללקוח
                                print(f"Sent client ID: {client_id}  date: {response}")
                        #############################825 --> 1601####################################
                            else:
                                print(f"User {req.payload} already exists.")
                                response = send_client_id(client_id, code=1601)  # שליחת תשובת כשל (1601)
                                conn.sendall(response)

                        # טיפול במפתח ציבורי (קוד 826)
                        ################################826 --> 1602#####################################
                        elif req.code == 826:  # קוד בקשה עבור מפתח ציבורי
                            payloadSplited = req.payload.split('\0')
                            username = payloadSplited[0]
                            public_key_pem = payloadSplited[1]

                            # הצפנת מפתח AES בעזרת המפתח הציבורי ושליחת תשובה ללקוח
                            response = send_encrypted_aes_key(username, public_key_pem)
                            conn.sendall(response)
                            print(f"Sent AES key to {username}.")
                        ################################828#####################################
                        # Handle file transfer request (code 828)
                        elif req.code == 828:  # קוד בקשה עבור שליחת קובץ
                            print("File transfer request received.")

                            # Extract Size Content (4 bytes) - Encrypted file size
                            size_content = struct.unpack('!I', data[24:28])[0]

                            # Extract Size File Orig (4 bytes) - Original file size
                            size_file_orig = struct.unpack('!I', data[28:32])[0]

                            # Extract Packet Number and Total Packets (4 bytes total)
                            packet_number, total_packets = struct.unpack('!HH', data[32:36])

                            # Extract the File Name (255 bytes, null-terminated)
                            file_name = data[36:291].decode('utf-8').rstrip('\x00')

                            # Extract the Encrypted File Content (remaining bytes)
                            content_message = data[291:291 + size_content]

                            print(f"File Transfer Details:")
                            print(f"File Name: {file_name}")
                            print(f"Encrypted File Size: {size_content} bytes")
                            print(f"Original File Size: {size_file_orig} bytes")
                            print(f"Packet {packet_number}/{total_packets}")

                            # Saving the encrypted file to disk
                            encrypted_file_path = f"client_files/received_{req.client_id}_{file_name}"
                            with open(encrypted_file_path, 'wb') as f:
                                f.write(content_message)

                            print(f"Encrypted file content saved as: {encrypted_file_path}")

                            # Load the AES key for this client from the file
                            aes_key = load_aes_key_from_file(req.client_id)

                            if not aes_key:
                                print(f"No AES key found for client {req.client_id}. Cannot decrypt the file.")
                            else:
                                # Initialize the AES decryption cipher
                                cipher_aes = AES.new(aes_key, AES.MODE_ECB)  # Assuming ECB mode, change if necessary

                                # Decrypt the encrypted content
                                decrypted_content = cipher_aes.decrypt(content_message)

                                # Save the decrypted file
                                decrypted_file_path = f"client_files/decrypted_{req.client_id}_{file_name}"
                                with open(decrypted_file_path, 'wb') as f:
                                    f.write(decrypted_content)

                                print(f"Decrypted file content saved as: {decrypted_file_path}")

                            # Calculate the CRC checksum using cksum's memcrc function
                            crc_value = memcrc(content_message)  # Use memcrc from cksum.py for the CRC calculation
                            print(f"CRC Checksum: {crc_value:#010x}")

                            # Build the response message (code 1603)
                            client_id = req.client_id.encode('utf-8').ljust(16,
                                                                            b'\x00')  # Client ID, padded to 16 bytes
                            size_content_bytes = struct.pack('!I', size_content)  # Size Content (4 bytes)
                            file_name_bytes = file_name.encode('utf-8').ljust(255, b'\x00')  # File Name (255 bytes)
                            crc_bytes = struct.pack('!I', crc_value)  # CRC (4 bytes)

                            # Construct the complete response
                            response_code = EResponseCode.Response_CRC_FILE_TRANSFER.value  # Use 1603 for CRC confirmation
                            response = struct.pack('!B H I', 1, response_code,
                                                   16 + 4 + 255 + 4)  # Header with payload size
                            response += client_id + size_content_bytes + file_name_bytes + crc_bytes

                            # Send the response back to the client
                            conn.sendall(response)
                            print(f"Sent CRC confirmation response to the client with ID: {req.client_id}")

                        ##################################################################################

                        # # Handle reconnect request (code 827)
                        # elif req.code == 827:  # קוד בקשה עבור התחברות חוזרת
                        #     username = req.payload.rstrip('\x00')  # Extract the username and remove the null terminator
                        #     print(f"Reconnect request received for user: {username}")
                        #
                        #     if username in registered_users:  # Check if the user is registered
                        #         print(f"User {username} exists. Reconnection confirmed.")
                        #
                        #         # Generate a new AES key (similar to code 1602 logic)
                        #         client_id = str(uuid.uuid4())[
                        #                     :16]  # Generate or use existing client ID, make sure it's 16 bytes
                        #         public_key_pem = req.payload  # You might need to retrieve the stored public key from memory
                        #         encrypted_aes_key = send_encrypted_aes_key(username,
                        #                                                    public_key_pem)  # Encrypt AES key using public key
                        #
                        #         # Send response for successful reconnection with AES key
                        #         response = struct.pack('!B H I', 1, 1605, len(encrypted_aes_key)) + client_id.encode(
                        #             'utf-8').ljust(16, b'\x00') + encrypted_aes_key
                        #         conn.sendall(response)
                        #         print(f"Sent AES key and reconnection confirmation with client ID: {client_id}")
                        #
                        #     else:
                        #         print(f"User {username} not found. Reconnection denied.")
                        #
                        #         # Send failure response (reconnection denied) with code 1606
                        #         client_id = str(uuid.uuid4())[
                        #                     :16]  # Generate or reuse existing client ID, ensure it's 16 bytes
                        #         response = struct.pack('!B H I', 1, 1606, 16) + client_id.encode('utf-8').ljust(16,
                        #                                                                                         b'\x00')
                        #         conn.sendall(response)
                        #         print(f"Sent reconnection denial for user: {username}")
                        #
                        #
                        # else:
                        #     print(f"Unknown request code: {client_id}")
                        #     conn.sendall(b"Unknown request")
            except KeyboardInterrupt:
                print("Server shutting down.")
                break
            except Exception as e:
                print(f"Unexpected error occurred: {e}")