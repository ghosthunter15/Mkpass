import argparse
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import unittest

def hash_password(password, salt=None, iterations=100000, algorithm="sha256"):
    """Hashes a password using PBKDF2.

    Args:
        password: The password to hash.
        salt: The salt to use for the hashing. If None, a random salt is generated.
        iterations: The number of iterations for PBKDF2.
        algorithm: The hashing algorithm to use.

    Returns:
        The hashed password and the salt.
    """

    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.get_algorithm(algorithm),
        length=32,
        salt=salt,
        iterations=iterations
    )
    hashed_password = kdf.derive(password)

    return hashed_password, salt

def main():
    parser = argparse.ArgumentParser(description="Hash a password")
    parser.add_argument("password", help="The password to hash")
    parser.add_argument("-s", "--salt", help="The salt to use for hashing")
    parser.add_argument("-i", "--iterations", type=int, default=100000, help="The number of iterations for PBKDF2")
    parser.add_argument("-a", "--algorithm", default="sha256", choices=["md5", "sha1", "sha256", "sha384", "sha512", "blake2b"], help="The hashing algorithm to use")

    args = parser.parse_args()

    hashed_password, salt = hash_password(args.password, args.salt, args.iterations, args.algorithm)
    print(f"Hashed password: {hashed_password.hex()}")
    print(f"Salt: {salt.hex()}")

if __name__ == "__main__":
    if __name__ == "__main__":
        main()

class TestHashPassword(unittest.TestCase):
    def test_hashing(self):
        password = b"my_password"
        salt = b"my_salt"
        expected_hash = b"your_expected_hash"  # Replace with the expected hashed value

        hashed_password, calculated_salt = hash_password(password, salt)

        self.assertEqual(hashed_password, expected_hash)
        self.assertEqual(salt, calculated_salt)

if __name__ == "__main__":
    unittest.main()
