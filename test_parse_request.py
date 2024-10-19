import unittest
import struct
from main import parse_request


class TestParseRequest(unittest.TestCase):

    def test_parse_request(self):
        # Create a mock request packet
        client_id = "test_client".ljust(16, '\x00')
        version = 1
        code = 825
        payload = "test_user"
        payload_size = len(payload)

        # Pack the data in two parts: big-endian for the code, little-endian for the rest
        packet = struct.pack(f'<16s B', client_id.encode('utf-8'), version) + struct.pack('!H', code) + struct.pack(
            '<I', payload_size) + struct.pack(f'{payload_size}s', payload.encode('utf-8'))

        # Expected values
        print("Expected values:")
        print(f"client_id: {client_id.strip()}")
        print(f"version: {version}")
        print(f"code: {code}")
        print(f"payload_size: {payload_size}")
        print(f"payload: {payload}")

        # Actual result
        req = parse_request(packet)
        print("\nActual parsed values:")
        print(f"client_id: {req.client_id}")
        print(f"version: {req.version}")
        print(f"code: {req.code}")
        print(f"payload_size: {req.payload_size}")
        print(f"payload: {req.payload}")

        # Compare expected and actual values
        self.assertEqual(req.client_id, "test_client")
        self.assertEqual(req.version, 1)
        self.assertEqual(req.code, 825)
        self.assertEqual(req.payload_size, len("test_user"))
        self.assertEqual(req.payload, "test_user")


if __name__ == '__main__':
    unittest.main()
