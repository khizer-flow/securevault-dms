import hashlib
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets


class CryptoManager:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def generate_rsa_keypair() -> tuple:
        """Generate RSA key pair (private, public)"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem.decode(), public_pem.decode()

    @staticmethod
    def generate_aes_key() -> bytes:
        """Generate random AES-256 key"""
        return secrets.token_bytes(32)

    @staticmethod
    def encrypt_with_aes(data: bytes, key: bytes) -> tuple:
        """Encrypt data using AES-256 in CBC mode"""
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        return encrypted_data, iv

    @staticmethod
    def decrypt_with_aes(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt data using AES-256"""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data

    @staticmethod
    def encrypt_with_rsa(data: bytes, public_key_pem: str) -> bytes:
        """Encrypt data using RSA public key"""
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    @staticmethod
    def decrypt_with_rsa(encrypted_data: bytes, private_key_pem: str) -> bytes:
        """Decrypt data using RSA private key"""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )

        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    @staticmethod
    def calculate_file_hash(file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    @staticmethod
    def verify_file_integrity(file_path: str, expected_hash: str) -> bool:
        """Verify file integrity using SHA-256 hash"""
        actual_hash = CryptoManager.calculate_file_hash(file_path)
        return actual_hash == expected_hash