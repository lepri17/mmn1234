import unittest
import struct
from main import send_client_id


class TestSendClientID(unittest.TestCase):

    def test_send_client_id_success(self):
        # Test case for sending client ID with success response (code 1600)
        client_id = "test_client_id"
        response_code = 1600
        print("\nSending client ID with success response:")

        # Expected result (manually constructing the expected response)
        version = 1
        payload = client_id.ljust(16, '\x00')  # Padding client_id to 16 bytes
        payload_size = len(payload)
        expected_response = struct.pack('!B H I', version, response_code, payload_size) + payload.encode('utf-8')

        print(
            f"Expected result: Version = {version}, Code = {response_code}, Payload size = {payload_size}, Client ID = {client_id}")

        # Actual result
        actual_response = send_client_id(client_id, response_code)
        print(f"Actual result: Response = {actual_response}")

        # Compare expected and actual results
        self.assertEqual(expected_response, actual_response)

    def test_send_client_id_failure(self):
        # Test case for sending client ID with failure response (code 1601)
        client_id = "test_client_fail"
        response_code = 1601
        print("\nSending client ID with failure response:")

        # Expected result (manually constructing the expected response)
        version = 1
        payload = client_id.ljust(16, '\x00')  # Padding client_id to 16 bytes
        payload_size = len(payload)
        expected_response = struct.pack('!B H I', version, response_code, payload_size) + payload.encode('utf-8')

        print(
            f"Expected result: Version = {version}, Code = {response_code}, Payload size = {payload_size}, Client ID = {client_id}")

        # Actual result
        actual_response = send_client_id(client_id, response_code)
        print(f"Actual result: Response = {actual_response}")

        # Compare expected and actual results
        self.assertEqual(expected_response, actual_response)


if __name__ == '__main__':
    unittest.main()
