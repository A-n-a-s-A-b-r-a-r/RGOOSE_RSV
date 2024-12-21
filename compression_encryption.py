import zlib , os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NONCE_SIZE = 12  # Nonce size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes


def compress_data(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress_data(data: bytes) -> bytes:
    return zlib.decompress(data)

def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> bytes:
    compressed_plaintext = compress_data(plaintext)
    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(compressed_plaintext) + encryptor.finalize()
    return nonce + ciphertext + encryptor.tag
