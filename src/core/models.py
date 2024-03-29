from src import db, bcrypt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from config import Config

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String, nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_email = db.Column(db.String, nullable=False)  # Email of the user who owns this password

    def __init__(self, website, password, user_email):
        self.website = website
        self.encrypted_password = self.encrypt_password(password)
        self.user_email = user_email

    def encrypt_password(self, password):
        # Derive a 256-bit key from the encryption key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt_value_here',  # Replace with a secure salt value
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(Config.ENCRYPTION_KEY.encode())

        # Encrypt the password using AES-256
        cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()
        return base64.urlsafe_b64encode(encrypted_password)

    def decrypt_password(self):
        # Derive a 256-bit key from the encryption key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt_value_here',  # Replace with the same secure salt value used for encryption
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(Config.ENCRYPTION_KEY.encode())

        # Decrypt the password using AES-256
        cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(base64.urlsafe_b64decode(self.encrypted_password)) + decryptor.finalize()
        try:
            decrypted_text = decrypted_bytes.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            decrypted_text = decrypted_bytes.decode('latin-1', errors='ignore')  # Try latin-1 encoding as fallback
        return decrypted_text


    def is_expired(self):
        return datetime.utcnow() - self.last_updated > timedelta(days=30)
