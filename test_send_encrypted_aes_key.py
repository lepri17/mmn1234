import unittest
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from main import send_encrypted_aes_key


class TestSendEncryptedAESKey(unittest.TestCase):

    def test_send_encrypted_aes_key(self):
        # Generate a temporary RSA key pair for the test
        rsa_key = RSA.generate(2048)
        public_key_pem = rsa_key.publickey().export_key()
        private_key = rsa_key  # Save the private key to decrypt later

        username = "test_user"
        print("\nSending encrypted AES key:")

        # Call the function to send the AES key encrypted with the public key
        actual_response = send_encrypted_aes_key(username, public_key_pem)

        # Extract the encrypted AES key from the response
        encrypted_aes_key = actual_response[7:]  # Skipping the 7-byte header (version, code, size)

        # Decrypt the AES key using the private key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Print the decrypted AES key (in hex format for readability)
        decrypted_aes_key_hex = decrypted_aes_key.hex()
        print(f"Decrypted AES key (hex): {decrypted_aes_key_hex}")

        # We can't predict the actual AES key (since it's randomly generated), but we can still check the structure
        version = 1
        response_code = 1602
        payload_size = len(encrypted_aes_key)

        # Manually constructing the expected header
        expected_header = struct.pack('!B H I', version, response_code, payload_size)

        # Check that the response starts with the correct header
        self.assertTrue(actual_response.startswith(expected_header), "Header does not match expected structure")

        # Print out what we are sending back to the client
        print(f"Expected result: Version = {version}, Code = {response_code}, Payload size = {payload_size}")
        print(f"Actual response sent to client: {actual_response}")

        # Additional test: verify the payload length matches the encrypted AES key size (it should be 256 bytes for RSA-2048)
        self.assertEqual(payload_size, 256, "The payload size does not match the expected length for encrypted AES key")


if __name__ == '__main__':
    unittest.main()
