import zlib , os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEADER_LENGTH = 18  # Length of the PDU header (example)
NONCE_SIZE = 12  # Nonce size for AES-GCM in bytes
TAG_SIZE = 16  # Tag size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes


def compress_data(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress_data(data: bytes) -> bytes:
    return zlib.decompress(data)

key = b'\xe3\x1e\xc3G\x8f\x98|\x15u\xf3`\xf2\xdc7\xe1 \x00\xdc\x1a\x85\t6B\x13\x8d\xcd\xfcu\xcd\x08{A'
# key = os.urandom(32)

def encrypt_aes_gcm(plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + ciphertext + encryptor.tag

def decrypt_aes_gcm(ciphertext_with_nonce_and_tag: bytes) -> bytes:
    nonce = ciphertext_with_nonce_and_tag[:NONCE_SIZE]
    ciphertext = ciphertext_with_nonce_and_tag[NONCE_SIZE:-TAG_SIZE]
    tag = ciphertext_with_nonce_and_tag[-TAG_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext