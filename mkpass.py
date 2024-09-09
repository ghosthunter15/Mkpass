import os
import argparse
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def get_algorithm(algorithm_name):
    """Returns the appropriate cryptography hash algorithm class."""
    algorithms = {
        "md5": hashes.MD5(),
        "sha1": hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
        "blake2b": hashes.BLAKE2b(64),  # BLAKE2b requires a digest size argument
    }
    return algorithms.get(algorithm_name.lower())

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
    else:
        if isinstance(salt, str):
            salt = salt.encode('utf-8')

    if isinstance(password, str):
        password = password.encode('utf-8')  # Ensure password is bytes

    algorithm = get_algorithm(algorithm)
    if algorithm is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    kdf = PBKDF2HMAC(
        algorithm=algorithm,
        length=32,
        salt=salt,
        iterations=iterations
    )
    hashed_password = kdf.derive(password)

    return hashed_password, salt

def main():
    parser = argparse.ArgumentParser(description="Hash a password")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s v1.5.0")
    parser.add_argument("password", help="The password to hash")
    parser.add_argument("-s", "--salt", help="The salt to use for hashing")
    parser.add_argument("-i", "--iterations", type=int, default=100000, help="The number of iterations for PBKDF2")
    parser.add_argument("-a", "--algorithm", default="sha256", choices=["md5", "sha1", "sha256", "sha384", "sha512", "blake2b"], help="The hashing algorithm to use")

    args = parser.parse_args()

    hashed_password, salt = hash_password(args.password, args.salt, args.iterations, args.algorithm)
    print(f"Hashed password: {hashed_password.hex()}")
    print(f"Salt: {salt.hex()}")

if __name__ == "__main__":
    main()
