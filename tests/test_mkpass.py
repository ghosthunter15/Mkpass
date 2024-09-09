import sys
import os
import unittest

# Add the parent directory to the sys.path so we can import mkpass
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the specific function
from mkpass import hash_password  # Ensure this matches the name of your module

class TestHashPassword(unittest.TestCase):
    def test_hashing(self):
# Test case for the hash_password function
        password = "password123"  # Pass the password as a string
        salt = os.urandom(16)  # Generate a random salt
        hashed_password, calculated_salt = hash_password(password, salt)

# Assertions to verify that the output is correct
        self.assertIsInstance(hashed_password, bytes)
        self.assertEqual(salt, calculated_salt)
        self.assertEqual(len(hashed_password), 32)  # Assuming a 32-byte length for the hash

if __name__ == "__main__":
    unittest.main()
