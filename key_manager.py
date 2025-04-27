import os
from jose import jwt  
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import PasswordHasher
import uuid
import base64
from typing import Optional
from database import db_connection

# AES Encryption
def get_aes_key():
    key = os.getenv("NOT_MY_KEY")
    if not key or len(key) < 32:
        raise ValueError("NOT_MY_KEY must be at least 32 chars")
    return key.encode()[:32]  # Use first 32 bytes

def encrypt_data(data: str) -> bytes:
    key = get_aes_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encrypted  # Prepend IV for storage

def decrypt_data(encrypted: bytes) -> str:
    key = get_aes_key()
    iv, ciphertext = encrypted[:16], encrypted[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# Key Management
class KeyManager:
    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16
        )

    def generate_key(self, expiry_minutes=60):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted_pem = encrypt_data(pem.decode())
        expiry = int((datetime.utcnow() + timedelta(minutes=expiry_minutes)).timestamp())

        with db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (encrypted_pem, expiry),
            )
            kid = cursor.lastrowid
            conn.commit()

        return {"kid": kid, "key": private_key, "exp": expiry}

    def register_user(self, username: str, email: str = None) -> str:
        password = str(uuid.uuid4())  # UUIDv4 password
        hashed_pw = self.ph.hash(password)

        with db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, email)
                VALUES (?, ?, ?)
                """,
                (username, hashed_pw, email),
            )
            conn.commit()

        return password  # Return plaintext password (send via email in prod)