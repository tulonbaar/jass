import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Any, Tuple

def get_aes_key(psk: str) -> bytes:
    """Ensures the key is exactly 32 bytes for AES-256."""
    key = psk.encode('utf-8')
    if len(key) > 32:
        return key[:32]
    return key.ljust(32, b'\x00')

def encrypt_payload(data: dict, psk: str) -> bytes:
    """Encrypts a dictionary to a JSON payload using AES-GCM."""
    key = get_aes_key(psk)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(data).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_payload(encrypted_data: bytes, psk: str) -> dict:
    """Decrypts AES-GCM data to a dictionary."""
    key = get_aes_key(psk)
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode('utf-8'))

