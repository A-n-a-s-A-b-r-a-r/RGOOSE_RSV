# certificateless_crypto.py
import hashlib
import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

# System parameters
class CLParameters:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.g = None  # Generator point (implicitly used by the EC implementation)
        self.kgc_pub_key = None  # Will be set by the KGC

# Key Generation Center (KGC)
class KGC:
    def __init__(self):
        self.params = CLParameters()
        self.master_key = ec.generate_private_key(self.params.curve)
        self.params.kgc_pub_key = self.master_key.public_key()
    
    def get_public_params(self):
        return self.params
    
    def extract_partial_private_key(self, identity):
        """Generate partial private key for a user"""
        id_hash = hashlib.sha256(identity.encode()).digest()
        # Use the master key to sign the hash of the identity
        signature = self.master_key.sign(
            id_hash,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    def get_kgc_public_key_bytes(self):
        """Get the KGC public key in bytes format for distribution"""
        return self.params.kgc_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

# User in the certificateless system
class CLUser:
    def __init__(self, identity, params):
        self.identity = identity
        self.params = params
        
        # User's self-generated key pair
        self.private_key = ec.generate_private_key(self.params.curve)
        self.public_key = self.private_key.public_key()
        
        # Will be set later by the KGC
        self.partial_private_key = None
        
    def set_partial_private_key(self, partial_key):
        """Set the partial private key received from the KGC"""
        self.partial_private_key = partial_key
    
    def get_user_public_key_bytes(self):
        """Get the user public key in bytes format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def encrypt(self, recipient_identity, recipient_public_key_bytes, message):
        """Encrypt a message for the recipient"""
        # Deserialize recipient's public key
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_bytes)
        
        # Ephemeral key for this encryption
        ephemeral_key = ec.generate_private_key(self.params.curve)
        shared_secret = ephemeral_key.exchange(ec.ECDH(), recipient_public_key)
        
        # Derive encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=recipient_identity.encode()
        ).derive(shared_secret)
        
        # Encrypt with AES-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, message, None)
        
        # Get the ephemeral public key to include with the ciphertext
        ephemeral_public_key_bytes = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'ephemeral_key': ephemeral_public_key_bytes,
            'nonce': nonce,
            'ciphertext': ciphertext
        }
    
    def decrypt(self, sender_identity, encrypted_data):
        """Decrypt a message from the sender"""
        ephemeral_public_key = serialization.load_pem_public_key(encrypted_data['ephemeral_key'])
        
        # Calculate shared secret
        shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Derive encryption key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=self.identity.encode()
        ).derive(shared_secret)
        
        # Decrypt
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(encrypted_data['nonce'], encrypted_data['ciphertext'], None)
        
        return plaintext
    
    def sign(self, message):
        """Sign a message using both private key components"""
        # Hash the message
        message_hash = hashlib.sha256(message).digest()
        
        # Sign with user's private key
        signature1 = self.private_key.sign(
            message_hash,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Combine both signatures (in a real system, you'd need a more sophisticated way to combine these)
        combined_signature = {
            'user_sig': signature1,
            'partial_key': self.partial_private_key
        }
        
        return combined_signature
    
    def verify(self, sender_identity, sender_public_key_bytes, message, signature, kgc_public_key_bytes):
        """Verify a signature from a sender"""
        # Deserialize keys
        sender_public_key = serialization.load_pem_public_key(sender_public_key_bytes)
        kgc_public_key = serialization.load_pem_public_key(kgc_public_key_bytes)
        
        # Hash the message and the sender's identity
        message_hash = hashlib.sha256(message).digest()
        id_hash = hashlib.sha256(sender_identity.encode()).digest()
        
        try:
            # Verify the user's signature component
            sender_public_key.verify(
                signature['user_sig'],
                message_hash,
                ec.ECDSA(hashes.SHA256())
            )
            
            # Verify the KGC's signature component (partial private key)
            kgc_public_key.verify(
                signature['partial_key'],
                id_hash,
                ec.ECDSA(hashes.SHA256())
            )
            
            return True
        except InvalidSignature:
            return False

# Helper function to serialize encrypted data for network transmission
def serialize_encrypted_data(encrypted_data):
    """Convert encrypted data to bytes for transmission"""
    return {
        'ephemeral_key': encrypted_data['ephemeral_key'],
        'nonce': encrypted_data['nonce'],
        'ciphertext': encrypted_data['ciphertext']
    }

# Helper function to deserialize encrypted data from network transmission
def deserialize_encrypted_data(data):
    """Convert network data back to encrypted data structure"""
    return {
        'ephemeral_key': data['ephemeral_key'],
        'nonce': data['nonce'],
        'ciphertext': data['ciphertext']
    }

# Helper function to serialize signature for network transmission
def serialize_signature(signature):
    """Convert signature to bytes for transmission"""
    return {
        'user_sig': signature['user_sig'],
        'partial_key': signature['partial_key']
    }

# Helper function to deserialize signature from network transmission
def deserialize_signature(data):
    """Convert network data back to signature structure"""
    return {
        'user_sig': data['user_sig'],
        'partial_key': data['partial_key']
    }
    
    
# Import the components
# from certificateless_crypto import KGC, CLUser, serialize_signature, deserialize_signature

def main():
    # Step 1: Setup KGC and get public parameters
    kgc = KGC()
    params = kgc.get_public_params()
    kgc_pub_key_bytes = kgc.get_kgc_public_key_bytes()

    # Step 2: Create two users (sender and receiver)
    sender = CLUser("sender@example.com", params)
    receiver = CLUser("receiver@example.com", params)

    # Step 3: KGC provides partial private keys
    sender_partial_key = kgc.extract_partial_private_key(sender.identity)
    receiver_partial_key = kgc.extract_partial_private_key(receiver.identity)

    sender.set_partial_private_key(sender_partial_key)
    receiver.set_partial_private_key(receiver_partial_key)

    # Step 4: sender sends an encrypted and signed message to receiver
    message = b"Hello receiver, this is sender!"
    encrypted = sender.encrypt(receiver.identity, receiver.get_user_public_key_bytes(), message)
    signature = sender.sign(message)

    # Serialize for transmission (e.g., over network)
    encrypted_serialized = encrypted  # already suitable as-is
    signature_serialized = serialize_signature(signature)

    print("\n=== Encrypted Message Sent ===")
    print(f"Ciphertext: {encrypted_serialized['ciphertext'].hex()}")
    print(f"Nonce: {encrypted_serialized['nonce'].hex()}")

    # Step 5: receiver receives the message and attempts to decrypt and verify
    decrypted = receiver.decrypt(sender.identity, encrypted_serialized)
    is_valid = receiver.verify(
        sender_identity=sender.identity,
        sender_public_key_bytes=sender.get_user_public_key_bytes(),
        message=decrypted,
        signature=deserialize_signature(signature_serialized),
        kgc_public_key_bytes=kgc_pub_key_bytes
    )

    print("\n=== Decrypted and Verified at receiver's End ===")
    print(f"Decrypted Message: {decrypted.decode()}")
    print(f"Signature Valid: {is_valid}")

if __name__ == "__main__":
    main()
