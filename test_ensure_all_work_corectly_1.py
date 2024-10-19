import unittest
import os
import struct
from main import check_and_register_user, parse_request, send_encrypted_aes_key, send_client_id

class TestServerOperations(unittest.TestCase):

    def setUp(self):
        # Create a temporary user_db.txt file for testing
        self.user_db_file = 'user_db.txt'
        with open(self.user_db_file, 'w') as f:
            f.write('existing_user\n')  # Simulate a user already in the database

    def tearDown(self):
        # Clean up the temporary user_db.txt after tests
        if os.path.exists(self.user_db_file):
            os.remove(self.user_db_file)

    def test_user_registration_existing_user(self):
        # Test registration for an existing user
        success, username = check_and_register_user('existing_user')
        self.assertFalse(success)
        self.assertEqual(username, 'existing_user')

    def test_user_registration_new_user(self):
        # Test registration for a new user
        success, username = check_and_register_user('new_user')
        self.assertTrue(success)
        self.assertEqual(username, 'new_user')
        # Ensure the user is stored in the file
        with open(self.user_db_file, 'r') as f:
            users = f.read().splitlines()
            self.assertIn('new_user', users)

    def test_parse_request(self):
        # Test that a request is correctly parsed
        client_id = "test_client".ljust(16, '\x00')
        version = 1
        code = 825
        payload = "test_user"
        payload_size = len(payload)
        packet = struct.pack(f'<16s B !H I {payload_size}s', client_id.encode('utf-8'), version, code, payload_size,
                             payload.encode('utf-8'))

        req = parse_request(packet)
        self.assertEqual(req.client_id.strip(), "test_client")
        self.assertEqual(req.version, 1)
        self.assertEqual(req.code, 825)
        self.assertEqual(req.payload_size, payload_size)
        self.assertEqual(req.payload, "test_user")

    def test_send_client_id(self):
        # Test that sending a client ID works as expected
        client_id = str(uuid.uuid4())
        response = send_client_id(client_id, code=1600)
        expected_version = 1
        expected_code = 1600
        payload = client_id.ljust(16, '\x00').encode('utf-8')
        header = struct.pack('!B H I', expected_version, expected_code, len(payload))

        self.assertEqual(response[:len(header)], header)
        self.assertEqual(response[len(header):], payload)

    def test_send_encrypted_aes_key(self):
        # Test that AES key encryption and sending works as expected
        username = "test_user"
        rsa_key = RSA.generate(2048)
        public_key_pem = rsa_key.publickey().export_key()
        response = send_encrypted_aes_key(username, public_key_pem)

        # Verify response format
        expected_version = 1
        expected_code = 1602
        header_size = struct.calcsize('!B H I')
        header = response[:header_size]
        version, code, payload_size = struct.unpack('!B H I', header)

        self.assertEqual(version, expected_version)
        self.assertEqual(code, expected_code)

        encrypted_key = response[header_size:]
        self.assertEqual(len(encrypted_key), payload_size)

        # Decrypt and verify the AES key
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        decrypted_aes_key = cipher_rsa.decrypt(encrypted_key)
        self.assertEqual(len(decrypted_aes_key), 32)  # AES key should be 32 bytes

if __name__ == '__main__':
    unittest.main()
