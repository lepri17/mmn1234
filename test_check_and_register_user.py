import unittest
from main import check_and_register_user, registered_users, send_client_id

class TestCheckAndRegisterUser(unittest.TestCase):

    def setUp(self):
        # Clear the registered_users set before each test
        registered_users.clear()
        print(f"\nBefore test, registered_users: {registered_users}")

    def test_register_new_user(self):
        # Test registering a new user
        username = "new_user"
        print("\nRegistering a new user:")

        # Expected result
        client_id = "new_user_id"
        expected_code = 1600  # Success registration code
        expected_response = send_client_id(client_id, expected_code)
        print(f"Expected result: Success = True, Response code = {expected_code}, Client ID = {client_id}")

        # Actual result
        success, returned_username = check_and_register_user(username)
        actual_response = send_client_id(client_id, expected_code)
        print(f"Actual result: Success = {success}, Response = {actual_response}")
        print(f"Registered users after: {registered_users}")  # Debug registered users

        # Compare expected and actual results
        self.assertTrue(success)
        self.assertEqual(returned_username, "new_user")
        self.assertIn("new_user", registered_users)  # Ensure the user is in the set
        self.assertEqual(expected_response, actual_response)

    def test_register_existing_user(self):
        # Register the user initially
        username = "existing_user"
        check_and_register_user(username)

        # Test registering the same user again
        print("\nRegistering an existing user:")

        # Expected result
        client_id = "existing_user_id"
        expected_code = 1601  # Failure registration code (user exists)
        expected_response = send_client_id(client_id, expected_code)
        print(f"Expected result: Success = False, Response code = {expected_code}, Client ID = {client_id}")

        # Actual result
        success, returned_username = check_and_register_user(username)
        actual_response = send_client_id(client_id, expected_code)
        print(f"Actual result: Success = {success}, Response = {actual_response}")
        print(f"Registered users after: {registered_users}")  # Debug registered users

        # Compare expected and actual results
        self.assertFalse(success)
        self.assertEqual(returned_username, "existing_user")
        self.assertEqual(len(registered_users), 1)  # Ensure the user is only added once
        self.assertEqual(expected_response, actual_response)

    def test_register_two_different_users(self):
        # Register the first user
        username1 = "user1"
        client_id1 = "user1_id"
        expected_code1 = 1600  # Success registration code for first user
        expected_response1 = send_client_id(client_id1, expected_code1)

        print("\nRegistering the first user:")
        success1, returned_username1 = check_and_register_user(username1)
        actual_response1 = send_client_id(client_id1, expected_code1)
        print(f"Expected result: Success = True, Client ID = {client_id1}")
        print(f"Actual result: Success = {success1}, Response = {actual_response1}")
        print(f"Registered users after first registration: {registered_users}")  # Debug registered users

        self.assertTrue(success1)
        self.assertEqual(returned_username1, "user1")
        self.assertIn("user1", registered_users)
        self.assertEqual(expected_response1, actual_response1)

        # Register the second user
        username2 = "user2"
        client_id2 = "user2_id"
        expected_code2 = 1600  # Success registration code for second user
        expected_response2 = send_client_id(client_id2, expected_code2)

        print("\nRegistering the second user:")
        success2, returned_username2 = check_and_register_user(username2)
        actual_response2 = send_client_id(client_id2, expected_code2)
        print(f"Expected result: Success = True, Client ID = {client_id2}")
        print(f"Actual result: Success = {success2}, Response = {actual_response2}")
        print(f"Registered users after second registration: {registered_users}")  # Debug registered users

        self.assertTrue(success2)
        self.assertEqual(returned_username2, "user2")
        self.assertIn("user2", registered_users)
        self.assertEqual(expected_response2, actual_response2)

        # Check that both users are in the registered_users set
        self.assertEqual(len(registered_users), 2)
        self.assertIn("user1", registered_users)
        self.assertIn("user2", registered_users)


if __name__ == '__main__':
    unittest.main()
