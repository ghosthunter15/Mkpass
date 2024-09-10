import sys
import os
import unittest

# Add the parent directory to the sys.path so we can import mkpass
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mkpass import hash_password

class TestHashPassword(unittest.TestCase):

    def test_empty_password(self):
        with self.assertRaises(ValueError):
            hash_password("")

    def test_invalid_algorithm(self):
        with self.assertRaises(ValueError):
            hash_password("password123", algorithm="unsupported_algo")

    def test_non_string_password(self):
        with self.assertRaises(TypeError):
            hash_password(12345)

    def test_low_iteration_count(self):
        with self.assertRaises(ValueError):
            hash_password("password123", iterations=1)

    def test_custom_salt(self):
        password = "password123"
        salt = os.urandom(16)
        hashed_password, calculated_salt = hash_password(password, salt)
        self.assertEqual(salt, calculated_salt)

    def test_empty_salt(self):
        password = "password123"
        salt = ""
        hashed_password, calculated_salt = hash_password(password, salt)
        self.assertIsNotNone(calculated_salt)
        self.assertNotEqual(calculated_salt, salt)

    def test_unicode_password(self):
        password = "pässwörd"
        salt = os.urandom(16)
        hashed_password, _ = hash_password(password, salt)
        self.assertIsInstance(hashed_password, bytes)

    def test_string_salt_encoding(self):
        password = "password123"
        salt = "somesalt"
        hashed_password, calculated_salt = hash_password(password, salt)
        self.assertIsInstance(calculated_salt, bytes)
        self.assertEqual(calculated_salt, salt.encode('utf-8'))

    def test_salt_generation(self):
        password = "password123"
        hashed_password, calculated_salt = hash_password(password)
        self.assertIsNotNone(calculated_salt)
        self.assertEqual(len(calculated_salt), 16)

    def test_hash_consistency(self):
        password = "password123"
        salt = os.urandom(16)
        hashed_password1, _ = hash_password(password, salt)
        hashed_password2, _ = hash_password(password, salt)
        self.assertEqual(hashed_password1, hashed_password2)

    def test_hash_length(self):
        password = "password123"
        salt = os.urandom(16)
        hashed_password, _ = hash_password(password, salt)
        self.assertEqual(len(hashed_password), 32)

    def test_different_algorithms(self):
        password = "password123"
        salt = os.urandom(16)
        hash_sha256, _ = hash_password(password, salt, algorithm="sha256")
        hash_sha512, _ = hash_password(password, salt, algorithm="sha512")
        self.assertNotEqual(hash_sha256, hash_sha512)

# Create a test suite
def suite():
    suite = unittest.TestSuite()
    suite.addTest(TestHashPassword('test_empty_password'))
    suite.addTest(TestHashPassword('test_invalid_algorithm'))
    suite.addTest(TestHashPassword('test_non_string_password'))
    suite.addTest(TestHashPassword('test_low_iteration_count'))
    suite.addTest(TestHashPassword('test_custom_salt'))
    suite.addTest(TestHashPassword('test_empty_salt'))
    suite.addTest(TestHashPassword('test_unicode_password'))
    suite.addTest(TestHashPassword('test_string_salt_encoding'))
    suite.addTest(TestHashPassword('test_salt_generation'))
    suite.addTest(TestHashPassword('test_hash_consistency'))
    suite.addTest(TestHashPassword('test_hash_length'))
    suite.addTest(TestHashPassword('test_different_algorithms'))
    return suite

if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
