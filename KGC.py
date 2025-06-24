# kgc.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class KeyGenerationCenter:
    def __init__(self):
        self.master_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.master_public = self.master_private.public_key()

    def generate_partial_private_key(self, identity: str):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(identity.encode('utf-8'))
        user_hash = digest.finalize()
        SECP256R1_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        scalar = int.from_bytes(user_hash, 'big') % SECP256R1_ORDER
        return ec.derive_private_key(scalar, ec.SECP256R1(), default_backend())

    def get_master_public_key(self):
        return self.master_public
