import base64
import struct

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

def send_client_id(client_id, code=1600):
    version = 1
    payload = client_id.bytes
    payload_size = len(payload)
    header = struct.pack('!B H I', version, code, payload_size)
    return header + payload

def send_encrypted_aes_key(username, public_key, code):
    aes_key_base64 = base64.b64encode(get_random_bytes(32)).decode('ascii')
    aes_key = base64.b64decode(aes_key_base64)
    public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    payload_size = len(encrypted_aes_key)
    header = struct.pack('!B H I', 1, code, payload_size)
    return header + encrypted_aes_key
