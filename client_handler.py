import struct
import base64
import uuid
from request_handler import parse_request
from user_management import check_and_register_user_in_file, load_public_key
from encryption_utils import send_encrypted_aes_key, load_aes_by_id
from constants import EResponseCode
from Crypto.Cipher import AES
from cksum import memcrc
def send_client_id(client_id, code=EResponseCode.Response_SUCCESS_REGISTRATION.value):
    version = 1
    payload = client_id.bytes
    payload_size = len(payload)
    header = struct.pack('!B H I', version, code, payload_size)
    response = header + payload
    return response

def handle_registration(req, conn):
    success, client_id = check_and_register_user_in_file(req.payload)
    if success:
        response = send_client_id(client_id)
        conn.sendall(response)
        print(f"Sent client ID: {client_id}  data: {response}")
    else:
        print(f"User {req.payload} already exists.")
        response = send_client_id(client_id, code=EResponseCode.Response_FAIL_REGISTRATION.value)
        conn.sendall(response)


def handle_public_key(req, conn):
    payload_split = req.payload.split('\0')
    username = payload_split[0]
    public_key_pem = payload_split[1]
    response = send_encrypted_aes_key(username, public_key_pem, EResponseCode.Response_GET_SEND_PUBLIC_KEY.value)
    conn.sendall(response)
    print(f"Sent AES key to {username}.")


def handle_file_transfer(req, data, conn):
    # Extract relevant information from the payload
    size_content = struct.unpack('!I', data[24:28])[0]
    size_file_orig = struct.unpack('!I', data[28:32])[0]
    packet_number, total_packets = struct.unpack('!HH', data[32:36])
    file_name1 = data[36:291]
    file_name = file_name1.split(b'\x00', 1)[0].decode('utf-8')  # Decode to remove byte formatting

    # Set the correct username and file path
    username = req.payload if isinstance(req.payload, str) else "default_username"
    encrypted_file_path = f"{username}_encrypted_file.txt"

    # Continue with handling the file content
    content_message = data[291:291 + size_content]

    # Ensure the file is written properly based on packet number
    if packet_number == 1:
        with open(encrypted_file_path, 'wb') as file:
            file.write(content_message)
    else:
        with open(encrypted_file_path, 'ab') as f:
            f.write(content_message)

    # Handle the file completion and decryption when all packets have been received
    if packet_number == total_packets:
        with open(encrypted_file_path, 'rb') as file:
            file_content = file.read()

        aes_key_base64 = load_aes_by_id(req.client_id)
        aes_key = base64.b64decode(aes_key_base64)
        if not aes_key:
            raise ValueError(f"No AES key found for client {req.client_id}. Cannot decrypt the file.")
        else:
            iv = b'\x00' * 16
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_content = cipher.decrypt(file_content)
            decrypted_content_copy = decrypted_content[:size_file_orig]

            # Save the decrypted content to a new file
            decrypted_file_path = f"{username}_decrypted_file.txt"
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_content_copy)

        # Calculate and send CRC response
        crc_value = memcrc(decrypted_content[:size_file_orig])
        client_id = uuid.uuid4().bytes
        size_content_bytes = struct.pack('!I', size_content)
        file_name_bytes = file_name.ljust(255, '\x00').encode('utf-8')
        crc_bytes = struct.pack('!I', crc_value)
        response_code = EResponseCode.Response_CRC_FILE_TRANSFER.value
        response = struct.pack('!B H I', 1, response_code, 16 + 4 + 255 + 4)
        response += client_id + size_content_bytes + file_name_bytes + crc_bytes
        conn.sendall(response)
        print(f"Sent CRC response to the client with ID: {req.client_id}")

def handle_crc_confirmation(conn):
    client_id = uuid.uuid4().bytes
    response_code = EResponseCode.Response_CONF_MESSAGE.value
    response = struct.pack('!B H I', 1, response_code, 16) + client_id
    conn.sendall(response)
    print(f"Sent confirmation response to the client.")


def handle_incorrect_crc(req, conn):
    file_name = req.payload.rstrip('\x00')
    client_id = uuid.uuid4().bytes
    response_code = EResponseCode.Response_CONF_MESSAGE.value
    response = struct.pack('!B H I', 1, response_code, 16) + client_id
    conn.sendall(response)
    print(f"Not correct {file_name}, sending again CRC")


def handle_reconnection(req, conn):
    username = req.payload.rstrip('\x00')
    public_key = load_public_key(username)
    if public_key:
        response = send_encrypted_aes_key(username, public_key, EResponseCode.Response_RECONNECT_CONF.value)
        conn.sendall(response)
        print(f"Sent AES key and reconnection confirmation for user: {username}")
    else:
        client_id = uuid.uuid4().bytes
        response = struct.pack('!B H I', 1, EResponseCode.Response_RECONNECT_IGNORE.value, 16) + client_id
        conn.sendall(response)
        print(f"Reconnection denied for user: {username}")


def handle_client(conn, addr):
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(8192)
            if not data:
                break
            req = parse_request(data)

            # Call respective functions based on request codes
            if req.code == 825:
                handle_registration(req, conn)
            elif req.code == 826:
                handle_public_key(req, conn)
            elif req.code == 828:
                handle_file_transfer(req, data, conn)
            elif req.code == 900:
                handle_crc_confirmation(conn)
            elif req.code in (901, 902):
                handle_incorrect_crc(req, conn)
            elif req.code == 827:
                handle_reconnection(req, conn)
            else:
                print(f"Unknown request code: {req.code}")
                conn.sendall(b"Unknown request")

        print(f"Closing connection with {addr}")
