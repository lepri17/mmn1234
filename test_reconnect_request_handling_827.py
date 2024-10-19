import unittest
import struct
import uuid
from main import registered_users, send_encrypted_aes_key, EResponseCode
from Crypto.PublicKey import RSA


class TestReconnectRequestHandling(unittest.TestCase):

    def setUp(self):
        registered_users.clear()
        # Generate a valid RSA key pair for the test
        self.rsa_key = RSA.generate(2048)
        self.public_key_pem = self.rsa_key.publickey().export_key()

    def test_reconnect_existing_user(self):
        username = "existing_user"
        registered_users.add(username)  # Simulate an existing user

        # Create a mock reconnect request
        client_id = str(uuid.uuid4())[:16]
        version = 1
        code = 827
        payload = username.ljust(255, '\x00')  # Null-terminated username
        payload_size = len(payload)

        request_packet = struct.pack(f'!16s B H I 255s', client_id.encode('utf-8'), version, code, payload_size,
                                     payload.encode('utf-8'))

        print("\nReconnect request for an existing user:")

        # Simulate the response logic for an existing user
        if username in registered_users:
            # Use the valid public key generated in setUp()
            encrypted_aes_key = send_encrypted_aes_key(username, self.public_key_pem.decode('utf-8'))
            expected_response = struct.pack('!B H I', 1, EResponseCode.Response_RECONNECT_CONF.value,
                                            len(encrypted_aes_key)) + client_id.encode('utf-8').ljust(16,
                                                                                                      b'\x00') + encrypted_aes_key

            # Expected success reconnect response with AES key
            print(f"Expected response: {expected_response}")
            # You would assert the actual response in a real test scenario

    def test_reconnect_non_existing_user(self):
        username = "non_existing_user"  # User is not registered
        client_id = str(uuid.uuid4())[:16]
        version = 1
        code = 827
        payload = username.ljust(255, '\x00')
        payload_size = len(payload)

        request_packet = struct.pack(f'!16s B H I 255s', client_id.encode('utf-8'), version, code, payload_size,
                                     payload.encode('utf-8'))

        print("\nReconnect request for a non-existing user:")

        # Simulate the response logic for a non-existing user
        if username not in registered_users:
            expected_response = struct.pack('!B H I', 1, EResponseCode.Response_RECONNECT_IGNORE.value,
                                            16) + client_id.encode('utf-8').ljust(16, b'\x00')

            # Expected failure reconnect response (user not found)
            print(f"Expected response: {expected_response}")
            # You would assert the actual response in a real test scenario


if __name__ == '__main__':
    unittest.main()
