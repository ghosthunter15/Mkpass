import os
import argparse

# import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Define a pepper (this should be stored securely, not hardcoded in production)
# YES I KNOW THIS SHOUD NOT BE IN HERE.
PEPPER = b"supersecretpepper"


def get_algorithm(algorithm_name):
    algorithms = {
        "md5": hashes.MD5(),
        "sha1": hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
        "blake2b": hashes.BLAKE2b(64),
    }
    return algorithms.get(algorithm_name.lower())


def hash_password(
    password, salt=None, iterations=100000, algorithm="sha256", use_pepper=False
):
    """
    Hashes a password using PBKDF2, with optional peppering.

    Args:
        password: The password to hash.
        salt: The salt to use for the hashing.
        If None, a random salt is generated.
        iterations: The number of iterations for PBKDF2.
        algorithm: The hashing algorithm to use.
        use_pepper:
        Boolean indicating whether to use a pepper with the password.

    Returns:
        The hashed password and the salt.
    """
    if not isinstance(password, (str, bytes)):
        raise TypeError("Password must be a string or bytes")
    if not password:
        raise ValueError("Password cannot be empty")

    if salt is None:
        salt = os.urandom(16)
    elif not salt:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = salt.encode("utf-8")

    if isinstance(password, str):
        try:
            password = password.encode("utf-8")
        except UnicodeEncodeError as e:
            raise ValueError(
                "Password contains characters that cannot be encoded to UTF-8"
            ) from e

    if use_pepper:
        password += PEPPER

    if iterations < 10000:
        raise ValueError("Iteration count is too low")

    algorithm = get_algorithm(algorithm)
    if algorithm is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    kdf = PBKDF2HMAC(
        algorithm=algorithm,
        length=32,  # Can be up to 64 bytes for SHA512 or blake2b.
        salt=salt,
        iterations=iterations,
    )
    hashed_password = kdf.derive(password)

    return hashed_password, salt


def main():
    parser = argparse.ArgumentParser(description="Hash a password")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s v2.0.0")
    parser.add_argument("password", help="The password to hash")
    parser.add_argument("-s", "--salt", help="The salt to use for hashing")
    parser.add_argument(
        "-i",
        "--iterations",
        type=int,
        default=100000,
        help="The number of iterations for PBKDF2",
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        default="sha256",
        choices=["md5", "sha1", "sha256", "sha384", "sha512", "blake2b"],
        help="The hashing algorithm to use",
    )

    # Add a new option for pepper
    parser.add_argument(
        "--pepper",
        action="store_true",
        help="Use a pepper when hashing the password",
    )

    args = parser.parse_args()

    # Pass the pepper option to the hash_password function
    hashed_password, salt = hash_password(
        args.password,
        args.salt,
        args.iterations,
        args.algorithm,
        use_pepper=args.pepper,
    )

    print(f"Hashed password: {hashed_password.hex()}")
    print(f"Salt: {salt.hex()}")


if __name__ == "__main__":
    main()
