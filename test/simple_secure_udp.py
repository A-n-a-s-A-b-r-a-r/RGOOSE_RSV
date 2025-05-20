import socket
import hashlib
import json
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import argparse

class SimpleSecureUDP:
    def __init__(self, is_sender=True, host='localhost', port=12345):
        self.is_sender = is_sender
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Use a pre-shared key for testing
        self.shared_key = hashlib.sha256(b"test_shared_key").digest()
        
    def start(self):
        if self.is_sender:
            self._run_sender()
        else:
            self._run_receiver()
    
    def _encrypt(self, message):
        """Encrypt a message using the shared key"""
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv + ciphertext
    
    def _decrypt(self, ciphertext):
        """Decrypt a message using the shared key"""
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def _run_sender(self):
        """Run as sender"""
        print(f"Starting sender on {self.host}:{self.port}")
        print("Type messages to send, or 'q' to quit")
        
        try:
            while True:
                message = input("> ")
                if message.lower() == 'q':
                    break
                    
                encrypted = self._encrypt(message.encode())
                self.socket.sendto(encrypted, (self.host, self.port))
        except KeyboardInterrupt:
            print("\nSender shutting down...")
        finally:
            self.socket.close()
    
    def _run_receiver(self):
        """Run as receiver"""
        print(f"Starting receiver on {self.host}:{self.port}")
        self.socket.bind((self.host, self.port))
        
        try:
            while True:
                data, addr = self.socket.recvfrom(4096)
                try:
                    decrypted = self._decrypt(data)
                    print(f"Received from {addr}: {decrypted.decode()}")
                except Exception as e:
                    print(f"Error decrypting message: {e}")
        except KeyboardInterrupt:
            print("\nReceiver shutting down...")
        finally:
            self.socket.close()

def main():
    parser = argparse.ArgumentParser(description='Simple Secure UDP Communication')
    parser.add_argument('mode', choices=['sender', 'receiver'], help='Run as sender or receiver')
    parser.add_argument('--host', default='localhost', help='Host address')
    parser.add_argument('--port', type=int, default=12345, help='Port number')
    
    args = parser.parse_args()
    
    secure_udp = SimpleSecureUDP(
        is_sender=(args.mode == 'sender'),
        host=args.host,
        port=args.port
    )
    
    secure_udp.start()

if __name__ == "__main__":
    main()