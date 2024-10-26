import base64
import uuid
import struct

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from user_management import save_publick_and_aes_key, load_client_id

def send_encrypted_aes_key(username, public_key, code):
    aes_key_base64 = base64.b64encode(get_random_bytes(32)).decode('ascii')
    save_publick_and_aes_key(username, aes_key_base64, public_key)
    aes_key = base64.b64decode(aes_key_base64)
    public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    version = 1
    client_id_str = load_client_id(username)
    client_id = uuid.UUID(client_id_str)
    clientI16 = client_id.bytes
    payload = clientI16 + encrypted_aes_key
    payload_size = len(payload)
    header = struct.pack('!B H I', version, code, payload_size)
    response = header + payload
    return response


def load_aes_by_id(clientid):
    end_marker = "#END#"
    with open('registed_name_uuid.txt', 'r') as file:
        content = file.read()
    records = content.split(end_marker)
    for record in records:
        name, id, aes, *_ = record.split(',')
        u = uuid.UUID(id)
        uuid_bytes = u.bytes
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
