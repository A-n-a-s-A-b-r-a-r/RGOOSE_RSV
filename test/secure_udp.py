# Add at the top of your secure_udp.py file:
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('secure_udp')

# secure_udp.py - Combining QKD-simulated key exchange with certificateless crypto for UDP
import socket
import time
import hashlib
import random
import base64
import json
import threading
import argparse
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ====================== QKD Simulation ========================
# Simulate quantum key distribution protocol to establish shared key

class QKDSimulation:
    def __init__(self, error_rate=0.05):
        self.error_rate = error_rate
    
    def generate_bits(self, n):
        """Generate n random bits"""
        return [random.randint(0, 1) for _ in range(n)]
    
    def generate_bases(self, n):
        """Generate n random bases (0 for rectilinear, 1 for diagonal)"""
        return [random.randint(0, 1) for _ in range(n)]
    
    def measure_bits(self, bits, bases_sent, bases_measured):
        """Simulate measurement of bits using specified bases"""
        results = []
        for i in range(len(bits)):
            if bases_sent[i] == bases_measured[i]:
                # Same basis - correct measurement with small error probability
                if random.random() < self.error_rate:
                    results.append(1 - bits[i])  # Bit flip due to error
                else:
                    results.append(bits[i])
            else:
                # Different basis - random result
                results.append(random.randint(0, 1))
        return results
    
    def get_sifted_key(self, bits, recipient_bases, sender_bases):
        """Get key bits where bases match"""
        sifted_key = []
        sifted_positions = []
        for i in range(len(bits)):
            if recipient_bases[i] == sender_bases[i]:
                sifted_key.append(bits[i])
                sifted_positions.append(i)
        return sifted_key, sifted_positions
    
    def check_error_rate(self, alice_key, bob_key, sample_size=100):
        """Check error rate on a random sample of bits"""
        if len(alice_key) < sample_size:
            sample_size = len(alice_key) // 4  # Use 25% of bits if fewer than sample_size

        if sample_size == 0:
            return 0, []
            
        # Select random positions to check
        check_positions = random.sample(range(len(alice_key)), sample_size)
        errors = 0
        
        for pos in check_positions:
            if alice_key[pos] != bob_key[pos]:
                errors += 1
                
        error_rate = errors / sample_size
        
        # Remove checked bits from key
        final_key_alice = [alice_key[i] for i in range(len(alice_key)) if i not in check_positions]
        final_key_bob = [bob_key[i] for i in range(len(bob_key)) if i not in check_positions]
        
        return error_rate, final_key_alice

    def bits_to_key(self, bits, length=32):
        """Convert bits to a cryptographic key"""
        # Ensure we have enough bits or repeat them if needed
        while len(bits) < length * 8:
            bits = bits + bits
        
        # Convert bits to bytes
        byte_array = bytearray()
        for i in range(0, min(len(bits), length * 8), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(bits):
                    byte_val |= (bits[i + j] << (7 - j))
            byte_array.append(byte_val)
            
        return bytes(byte_array[:length])

# ====================== Certificateless Crypto ========================

class CertificatelessCrypto:
    def __init__(self):
        # Generate system parameters for a simplified certificateless system
        self.identity = socket.gethostname() + str(random.randint(1000, 9999))
        self.secret_value = self._generate_random_bytes(32)
        self.partial_key = None
        
    def _generate_random_bytes(self, length):
        return os.urandom(length)
    
    def set_partial_key(self, partial_key):
        """Set partial key - would be received from KGC in a real system"""
        self.partial_key = partial_key
        
    def generate_partial_key(self, peer_id):
        """Generate a partial key for a peer (simulating KGC role)"""
        # In a real system, this would be done by a trusted KGC
        h = hashlib.sha256()
        h.update(peer_id.encode())
        h.update(self.secret_value)
        return h.digest()
        
    def get_full_private_key(self):
        """Get full private key by combining partial key and secret value"""
        if not self.partial_key:
            raise ValueError("Partial key not set yet")
            
        h = hashlib.sha256()
        h.update(self.partial_key)
        h.update(self.secret_value)
        return h.digest()
        
    def get_public_key(self):
        """Get public key component"""
        h = hashlib.sha256()
        h.update(b"public_key")
        h.update(self.secret_value)
        return h.digest()
        
    def get_identity(self):
        """Get identity string"""
        return self.identity
        
    def encrypt(self, message, peer_id, peer_public_key, shared_key):
        """Encrypt a message using peer's identity, public key and shared key from QKD"""
        # Combine all keys for encryption
        h = hashlib.sha256()
        h.update(peer_id.encode())
        h.update(peer_public_key)
        h.update(shared_key)
        encryption_key = h.digest()
        
        # Use AES for actual encryption
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv + ciphertext
        
    def decrypt(self, ciphertext, peer_id, peer_public_key, shared_key):
        """Decrypt a message using full private key and shared key from QKD"""
        # Combine all keys for decryption
        h = hashlib.sha256()
        h.update(peer_id.encode())
        h.update(peer_public_key)
        h.update(shared_key)
        decryption_key = h.digest()
        
        # Extract IV and ciphertext
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        # Use AES for actual decryption
        cipher = Cipher(algorithms.AES(decryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext

# ====================== UDP Communication ========================

class SecureUDP:
    def __init__(self, is_sender=True, host='localhost', port=12345):
        self.is_sender = is_sender
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.qkd = QKDSimulation()
        self.crypto = CertificatelessCrypto()
        self.shared_key = None
        self.peer_id = None
        self.peer_public_key = None
        
    def start(self):
        """Start the UDP communication"""
        if self.is_sender:
            self._run_sender()
        else:
            self._run_receiver()
            
    def _run_sender(self):
        """Run as sender"""
        print(f"Starting sender on {self.host}:{self.port}")
        
        # Step 1: Initial key exchange handshake
        self._initiate_key_exchange()
        
        # Step 2: Start sending encrypted messages
        print("Starting to send encrypted messages...")
        try:
            while True:
                message = input("Enter message to send (or 'q' to quit): ")
                if message.lower() == 'q':
                    break
                    
                encrypted = self.crypto.encrypt(
                    message.encode(), 
                    self.peer_id, 
                    self.peer_public_key, 
                    self.shared_key
                )
                self.socket.sendto(encrypted, (self.host, self.port))
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nSender shutting down...")
        finally:
            self.socket.close()
            
    def _run_receiver(self):
        """Run as receiver"""
        print(f"Starting receiver on {self.host}:{self.port}")
        self.socket.bind((self.host, self.port))
        
        # Separate thread for handling key exchange
        key_exchange_thread = threading.Thread(target=self._handle_key_exchange)
        key_exchange_thread.daemon = True
        key_exchange_thread.start()
        
        # Main thread for receiving messages
        try:
            while True:
                data, addr = self.socket.recvfrom(4096)
                
                # Check if this is a key exchange message
                try:
                    message = json.loads(data.decode())
                    if 'type' in message and message['type'].startswith('qkd_'):
                        continue  # Let the key exchange thread handle this
                except:
                    # If not JSON, it's an encrypted message
                    if self.shared_key and self.peer_id and self.peer_public_key:
                        try:
                            decrypted = self.crypto.decrypt(
                                data, 
                                self.peer_id, 
                                self.peer_public_key, 
                                self.shared_key
                            )
                            print(f"\nReceived: {decrypted.decode()}")
                        except Exception as e:
                            print(f"Decryption error: {e}")
                    else:
                        print("Received encrypted message but key exchange not complete")
        except KeyboardInterrupt:
            print("\nReceiver shutting down...")
        finally:
            self.socket.close()
            
    def _initiate_key_exchange(self):
        """Initiate key exchange as sender"""
        print("Initiating key exchange...")

        # Step 1: QKD protocol simulation
        # Generate random bits and bases
        num_bits = 1000
        bits = self.qkd.generate_bits(num_bits)
        bases = self.qkd.generate_bases(num_bits)

        # Send initial handshake with identity and public key
        handshake_msg = {
            'type': 'qkd_init',
            'identity': self.crypto.get_identity(),
            'public_key': base64.b64encode(self.crypto.get_public_key()).decode()
        }
        self.socket.sendto(json.dumps(handshake_msg).encode(), (self.host, self.port))

        # Wait for receiver's handshake response
        try:
            # Increase timeout to 10 seconds
            self.socket.settimeout(10.0)
            print("Waiting for receiver acknowledgment...")
            data, addr = self.socket.recvfrom(4096)
            response = json.loads(data.decode())

            if response['type'] == 'qkd_ack':
                self.peer_id = response['identity']
                self.peer_public_key = base64.b64decode(response['public_key'])
                print(f"Connected to peer: {self.peer_id}")

                # Generate partial key for peer
                partial_key = self.crypto.generate_partial_key(self.peer_id)

                # Send QKD data
                qkd_msg = {
                    'type': 'qkd_bits',
                    'bits': bits,
                    'bases': bases,
                    'partial_key': base64.b64encode(partial_key).decode()
                }
                print("Sending QKD bits and bases...")
                self.socket.sendto(json.dumps(qkd_msg).encode(), (self.host, self.port))

                # Wait for receiver's measurement bases
                print("Waiting for receiver's measurement bases...")
                data, addr = self.socket.recvfrom(4096)
                receiver_response = json.loads(data.decode())

                if receiver_response['type'] == 'qkd_bases':
                    receiver_bases = receiver_response['bases']
                    self.crypto.set_partial_key(base64.b64decode(receiver_response['partial_key']))

                    # Calculate sifted key
                    sifted_key, positions = self.qkd.get_sifted_key(bits, receiver_bases, bases)

                    # Send positions of matching bases
                    match_msg = {
                        'type': 'qkd_matches',
                        'positions': positions
                    }
                    print("Sending matching positions...")
                    self.socket.sendto(json.dumps(match_msg).encode(), (self.host, self.port))

                    # Wait for error check results
                    print("Waiting for error check results...")
                    data, addr = self.socket.recvfrom(4096)
                    error_msg = json.loads(data.decode())

                    if error_msg['type'] == 'qkd_error_check':
                        error_rate = error_msg['error_rate']
                        print(f"QKD error rate: {error_rate:.2%}")

                        if error_rate < 0.15:  # Accept if error rate is reasonable
                            # Use matches to form key
                            self.shared_key = self.qkd.bits_to_key(sifted_key)
                            print("Key exchange successful!")

                            # Send confirmation
                            confirm_msg = {
                                'type': 'qkd_complete',
                                'status': 'success'
                            }
                            self.socket.sendto(json.dumps(confirm_msg).encode(), (self.host, self.port))
                            return True
                        else:
                            print("Error rate too high, possible eavesdropping!")

            print("Key exchange failed!")
            return False

        
        except Exception as e:
            print(f"Error during key exchange: {e}")
            return False
        finally:
            self.socket.settimeout(None)



    def _handle_key_exchange(self):
        """Handle key exchange requests as receiver"""
        logger.debug("Key exchange handler started")
        while True:
            try:
                if self.shared_key:
                    # If we already have a key, don't need to continue exchange
                    time.sleep(1)
                    continue
                    
                # Wait for initial handshake
                logger.debug("Waiting for key exchange messages...")
                data, addr = self.socket.recvfrom(4096)
                logger.debug(f"Received data of length {len(data)} from {addr}")
                
                try:
                    message = json.loads(data.decode())
                    logger.debug(f"Received message type: {message.get('type', 'unknown')}")
                    
                    if message['type'] == 'qkd_init':
                        self.peer_id = message['identity']
                        self.peer_public_key = base64.b64decode(message['public_key'])
                        logger.info(f"Received key exchange request from: {self.peer_id}")
                        
                        # Send ack with our identity and public key
                        ack_msg = {
                            'type': 'qkd_ack',
                            'identity': self.crypto.get_identity(),
                            'public_key': base64.b64encode(self.crypto.get_public_key()).decode()
                        }
                        logger.debug("Sending acknowledgment...")
                        self.socket.sendto(json.dumps(ack_msg).encode(), addr)
                        
                    elif message['type'] == 'qkd_bits' and self.peer_id:
                        logger.debug("Received QKD bits and bases")
                        # Generate partial key for peer
                        partial_key = self.crypto.generate_partial_key(self.peer_id)
                        self.crypto.set_partial_key(base64.b64decode(message['partial_key']))
                        
                        # Receive bits and bases from sender
                        sender_bits = message['bits']
                        sender_bases = message['bases']
                        
                        # Generate our own random measurement bases
                        our_bases = self.qkd.generate_bases(len(sender_bits))
                        
                        # Measure the received bits with our bases
                        measurements = self.qkd.measure_bits(sender_bits, sender_bases, our_bases)
                        
                        # Send our bases back
                        bases_msg = {
                            'type': 'qkd_bases',
                            'bases': our_bases,
                            'partial_key': base64.b64encode(partial_key).decode()
                        }
                        logger.debug("Sending our measurement bases...")
                        self.socket.sendto(json.dumps(bases_msg).encode(), addr)
                        
                    elif message['type'] == 'qkd_matches' and self.peer_id:
                        logger.debug("Received matching positions")
                        # Extract matched positions
                        positions = message['positions']
                        
                        # Simulate error checking (normally would exchange check bits)
                        # Real implementation would verify subset of key bits
                        error_rate = random.uniform(0.0, 0.1)  # Simulate 0-10% error
                        
                        # Send error check result
                        error_msg = {
                            'type': 'qkd_error_check',
                            'error_rate': error_rate
                        }
                        logger.debug(f"Sending error check result: {error_rate:.2%}")
                        self.socket.sendto(json.dumps(error_msg).encode(), addr)
                        
                    elif message['type'] == 'qkd_complete' and self.peer_id:
                        if message['status'] == 'success':
                            # Simulate forming the same key
                            # In real QKD, both parties would derive the same key from matched measurements
                            key_material = hashlib.sha256(f"{self.peer_id}{self.crypto.get_identity()}".encode()).digest    ()
                            self.shared_key = key_material[:32]  # Use 256 bits
                            logger.info("Key exchange completed successfully!")
                        else:
                            logger.warning("Key exchange failed!")
                            
                except json.JSONDecodeError:
                    logger.debug("Received non-JSON message, might be encrypted data")
                    continue  # Not a JSON message, ignore
                    
            except Exception as e:
                logger.error(f"Error in key exchange handler: {e}")
                time.sleep(0.5)
# ====================== Main Program ========================

def main():
    parser = argparse.ArgumentParser(description='Secure UDP Communication with QKD and Certificateless Crypto')
    parser.add_argument('mode', choices=['sender', 'receiver'], help='Run as sender or receiver')
    parser.add_argument('--host', default='localhost', help='Host address')
    parser.add_argument('--port', type=int, default=12345, help='Port number')
    
    args = parser.parse_args()
    
    secure_udp = SecureUDP(
        is_sender=(args.mode == 'sender'),
        host=args.host,
        port=args.port
    )
    
    secure_udp.start()

if __name__ == "__main__":
    main()