from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------
# 🔐 Encryption Key Setup
# -----------------------------
# Your secret key (must match the one used to encrypt/decrypt files)
SECRET_KEY = b'OQpa5v_q4qL-hEcerr_BzQ4UUbcA3QzHXA4dtIL9MZE='

fernet = Fernet(SECRET_KEY)

# -----------------------------
# 🔒 File Encryption & Decryption
# -----------------------------
def encrypt_bytes(data: bytes) -> bytes:
    return fernet.encrypt(data)

def decrypt_bytes(data: bytes) -> bytes:
    return fernet.decrypt(data)

# -----------------------------
# 🔑 Password Hashing
# -----------------------------
def hash_password(password: str) -> str:
    """Hash a plaintext password for secure storage."""
    return generate_password_hash(password)

def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a hashed one."""
    return check_password_hash(hashed, password)
