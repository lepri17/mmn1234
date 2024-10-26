import struct
from enum import Enum
from encryption_utils import send_client_id, send_encrypted_aes_key
from user_management import check_and_register_user_in_file, save_publick_and_aes_key, load_client_id

class EResponseCode(Enum):
    Response_SUCCESS_REGISTRATION = 1600
    Response_FAIL_REGISTRATION = 1601
    Response_GET_SEND_PUBLIC_KEY = 1602
    Response_CRC_FILE_TRANSFER = 1603
    Response_CONF_MESSAGE = 1604
    Response_RECONNECT_CONF = 1605
    Response_RECONNECT_IGNORE = 1606

class Request:
    def __init__(self, client_id, version, code, payload_size, payload):
        self.client_id = client_id
        self.version = version
        self.code = code
        self.payload_size = payload_size
        self.payload = payload

def parse_request(data):
    client_id = data[:16]
    version = struct.unpack('B', data[16:17])[0]
    code = struct.unpack('!H', data[18:20])[0]
    payload_size = struct.unpack('!I', data[20:24])[0]
    if code != 828:
        payload = data[24:24 + payload_size].decode('utf-8')
    else:
        payload = data[24:24 + payload_size]
    return Request(client_id, version, code, payload_size, payload)

def handle_client(conn, addr):
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(8192)
            if not data:
                break
            req = parse_request(data)
            if req.code == 825:
                success, client_id = check_and_register_user_in_file(req.payload)
                if success:
                    response = send_client_id(client_id)
                    conn.sendall(response)
                    print(f"Sent client ID: {client_id}")
                else:
                    response = send_client_id(client_id, code=1601)
                    conn.sendall(response)
            elif req.code == 826:
                payload_splitted = req.payload.split('\0')
                username, public_key_pem = payload_splitted[0], payload_splitted[1]
                response = send_encrypted_aes_key(username, public_key_pem, EResponseCode.Response_GET_SEND_PUBLIC_KEY.value)
                conn.sendall(response)
                print(f"Sent AES key to {username}.")
            # Add more elif conditions for other codes
    print(f"Closing connection with {addr}")
