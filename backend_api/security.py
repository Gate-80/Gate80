import base64
import hashlib
import hmac
from secrets import token_bytes


PASSWORD_HASH_ALGORITHM = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 260_000


def hash_password(password: str) -> str:
    salt = token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    encoded_salt = base64.urlsafe_b64encode(salt).decode("ascii")
    encoded_digest = base64.urlsafe_b64encode(digest).decode("ascii")
    return (
        f"{PASSWORD_HASH_ALGORITHM}"
        f"${PASSWORD_HASH_ITERATIONS}"
        f"${encoded_salt}"
        f"${encoded_digest}"
    )


def verify_password(password: str, stored_password: str) -> bool:
    if not stored_password:
        return False

    parts = stored_password.split("$")
    if len(parts) != 4 or parts[0] != PASSWORD_HASH_ALGORITHM:
        return hmac.compare_digest(stored_password, password)

    _, iterations_text, encoded_salt, encoded_digest = parts
    try:
        iterations = int(iterations_text)
        salt = base64.urlsafe_b64decode(encoded_salt.encode("ascii"))
        expected_digest = base64.urlsafe_b64decode(encoded_digest.encode("ascii"))
    except (TypeError, ValueError):
        return False

    actual_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual_digest, expected_digest)


def password_needs_rehash(stored_password: str) -> bool:
    return not stored_password.startswith(f"{PASSWORD_HASH_ALGORITHM}${PASSWORD_HASH_ITERATIONS}$")
