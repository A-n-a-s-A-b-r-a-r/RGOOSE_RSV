"""
Server application using certificateless encryption for secure communication.

This server:
1. Sets up a KGC (Key Generation Center)
2. Creates its own identity in the certificateless system
3. Listens for client connections
4. Receives and decrypts messages from clients
"""

import socket
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
import os
import base64

# The order of the SECP256R1 curve
SECP256R1_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

class KGC:
    """Key Generation Center for certificateless encryption"""
    
    def __init__(self):
        # Generate master key
        self.master_private_key = ec.generate_private_key(ec.SECP256R1())
        self.master_public_key = self.master_private_key.public_key()
        self.curve = ec.SECP256R1()
    
    def generate_partial_private_key(self, user_id):
        """Generate a partial private key for a user based on their identity"""
        # Hash the user ID
        digest = hashes.Hash(hashes.SHA256())
        digest.update(user_id.encode())
        user_id_hash = digest.finalize()
        
        # Use the hash to derive a deterministic private key
        derived_private_key = int.from_bytes(user_id_hash, byteorder='big') % SECP256R1_ORDER
        
        # Sign the user ID with the master key to create the partial private key
        signature = self.master_private_key.sign(
            user_id.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        
        return {
            'derived_key': derived_private_key,
            'signature': signature
        }
    
    def get_public_params(self):
        """Get the public parameters of the system"""
        return {
            'master_public_key': self.master_public_key
        }


class User:
    """User in a certificateless encryption system"""
    
    def __init__(self, user_id, kgc):
        self.user_id = user_id
        
        # Get system parameters from KGC
        kgc_params = kgc.get_public_params()
        self.master_public_key = kgc_params['master_public_key']
        
        # Get partial private key from KGC
        self.partial_private_key = kgc.generate_partial_private_key(user_id)
        
        # Generate user's own key pair
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        
        # Combine to create full key pair for certificateless encryption
        # Note: This is a simplified representation for demonstration
        self.full_public_key = self.public_key
    
    def encrypt_message(self, recipient, message):
        """Encrypt a message for a recipient"""
        # Generate an ephemeral key pair
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # Perform key agreement with recipient's public key
        shared_key = ephemeral_private_key.exchange(
            ec.ECDH(),
            recipient.full_public_key
        )
        
        # Derive encryption key from shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'certificateless-encryption'
        ).derive(shared_key)
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Encrypt the message
        encryptor = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(iv)
        ).encryptor()
        
        # Pad the message to be a multiple of 16 bytes
        padded_message = message.encode()
        padding_length = 16 - (len(padded_message) % 16)
        padded_message += bytes([padding_length]) * padding_length
        
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        
        # Return the encrypted message and necessary parameters
        return {
            'ephemeral_public_key': ephemeral_public_key,
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode()
        }
    
    def decrypt_message(self, encrypted_data):
        """Decrypt a message"""
        # Extract parameters
        ephemeral_public_key = encrypted_data['ephemeral_public_key']
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Perform key agreement with the ephemeral public key
        shared_key = self.private_key.exchange(
            ec.ECDH(),
            ephemeral_public_key
        )
        
        # Derive decryption key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'certificateless-encryption'
        ).derive(shared_key)
        
        # Decrypt the message
        decryptor = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(iv)
        ).decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext.decode()


class PublicKeySerializer:
    """Helper class to serialize and deserialize public keys"""
    
    @staticmethod
    def serialize_public_key(public_key):
        """Convert a public key to bytes for transmission"""
        return public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def deserialize_public_key(serialized_key):
        """Convert serialized bytes back to a public key"""
        return load_pem_public_key(serialized_key)


def run_server():
    # Create KGC and server identity
    kgc = KGC()
    server_user = User("server@example.com", kgc)
    
    # Set up server socket
    host = '127.0.0.1'
    port = 65432
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print(f"Server is listening on {host}:{port}")
    
    # Accept connections
    while True:
        client_socket, address = server_socket.accept()
        print(f"Connected to client at {address}")
        
        try:
            # Exchange public keys
            # Send server's public key
            serialized_server_pk = PublicKeySerializer.serialize_public_key(server_user.full_public_key)
            client_socket.sendall(len(serialized_server_pk).to_bytes(4, byteorder='big'))
            client_socket.sendall(serialized_server_pk)
            
            # Receive client's public key
            data_size = int.from_bytes(client_socket.recv(4), byteorder='big')
            serialized_client_pk = b''
            while len(serialized_client_pk) < data_size:
                chunk = client_socket.recv(min(4096, data_size - len(serialized_client_pk)))
                if not chunk:
                    break
                serialized_client_pk += chunk
            
            client_public_key = PublicKeySerializer.deserialize_public_key(serialized_client_pk)
            
            # Create a mock client user object just to hold the public key
            class MockUser:
                pass
            
            client_user = MockUser()
            client_user.full_public_key = client_public_key
            
            print("Public key exchange completed successfully")
            
            # Receive encrypted message from client
            data_size = int.from_bytes(client_socket.recv(4), byteorder='big')
            encrypted_data_bytes = b''
            while len(encrypted_data_bytes) < data_size:
                chunk = client_socket.recv(min(4096, data_size - len(encrypted_data_bytes)))
                if not chunk:
                    break
                encrypted_data_bytes += chunk
            
            # Parse the encrypted data
            encrypted_data_dict = json.loads(encrypted_data_bytes.decode())
            
            # Deserialize ephemeral public key
            encrypted_data_dict['ephemeral_public_key'] = PublicKeySerializer.deserialize_public_key(
                base64.b64decode(encrypted_data_dict['ephemeral_public_key'])
            )
            
            # Decrypt the message
            decrypted_message = server_user.decrypt_message(encrypted_data_dict)
            print(f"Received encrypted message. Decrypted content: {decrypted_message}")
            
            # Send acknowledgment
            response = "Message received and decrypted successfully!"
            encrypted_response = server_user.encrypt_message(client_user, response)
            
            # Serialize ephemeral public key for transmission
            encrypted_response['ephemeral_public_key'] = base64.b64encode(
                PublicKeySerializer.serialize_public_key(encrypted_response['ephemeral_public_key'])
            ).decode()
            
            # Send encrypted response
            response_bytes = json.dumps(encrypted_response).encode()
            client_socket.sendall(len(response_bytes).to_bytes(4, byteorder='big'))
            client_socket.sendall(response_bytes)
            
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()
            print("Connection closed")


if __name__ == "__main__":
    run_server()