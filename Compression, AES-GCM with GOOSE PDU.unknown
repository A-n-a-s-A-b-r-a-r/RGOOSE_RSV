import zlib
import os
import struct
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define constants for GOOSE PDU structure
HEADER_LENGTH = 18  # Length of the PDU header (example)
NONCE_SIZE = 12  # Nonce size for AES-GCM in bytes
TAG_SIZE = 16  # Tag size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes

def create_goose_pdu():
    # Create a payload with PMU data
    sequence_number = 1  # Example sequence number
    timestamp = int(time.time())  # Current Unix timestamp
    voltage_phasor = (1.0, 0.5)  # Magnitude and angle in radians
    current_phasor = (0.8, 1.0)  # Magnitude and angle in radians

    # Format for PMU payload
    payload_format = 'I I ff ff'  # I: unsigned int (4 bytes), f: float (4 bytes)
    payload = struct.pack(
        payload_format,
        sequence_number,
        timestamp,
        voltage_phasor[0],
        voltage_phasor[1],
        current_phasor[0],
        current_phasor[1]
    )

    # PDU header
    pdu_identifier = 0x1234  # Example PDU Identifier
    reserved = 0x00
    data_change_info = 0x01  # Example value indicating data change information
    simulation = 0x00  # Example value indicating no simulation
    application_id = 0x5678  # Example Application ID
    application_length = len(payload)

    header_format = 'H B B B H H I'
    header = struct.pack(
        header_format,
        pdu_identifier,
        reserved,
        data_change_info,
        simulation,
        application_id,
        application_length,
        timestamp
    )

    return header + payload

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

def decrypt_aes_gcm(ciphertext_with_nonce_and_tag: bytes, key: bytes) -> bytes:
    nonce = ciphertext_with_nonce_and_tag[:NONCE_SIZE]
    ciphertext = ciphertext_with_nonce_and_tag[NONCE_SIZE:-TAG_SIZE]
    tag = ciphertext_with_nonce_and_tag[-TAG_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    compressed_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return decompress_data(compressed_plaintext)

def decode_goose_pdu(pdu: bytes):
    # Extract the header and payload
    header = pdu[:HEADER_LENGTH]
    payload = pdu[HEADER_LENGTH:]

    # Decode header
    header_format = 'H B B B H H I'
    header_fields = struct.unpack(header_format, header)
    pdu_identifier = header_fields[0]
    reserved = header_fields[1]
    data_change_info = header_fields[2]
    simulation = header_fields[3]
    application_id = header_fields[4]
    application_length = header_fields[5]
    timestamp = header_fields[6]

    # Decode payload
    payload_format = 'I I ff ff'
    decoded_data = struct.unpack(payload_format, payload)
    
    sequence_number = decoded_data[0]
    pmu_timestamp = datetime.fromtimestamp(decoded_data[1])
    voltage_phasor = (decoded_data[2], decoded_data[3])
    current_phasor = (decoded_data[4], decoded_data[5])
    
    return {
        'PDU Identifier': pdu_identifier,
        'Reserved': reserved,
        'Data Change Info': data_change_info,
        'Simulation': simulation,
        'Application ID': application_id,
        'Application Length': application_length,
        'Timestamp': timestamp,
        'Sequence Number': sequence_number,
        'PMU Timestamp': pmu_timestamp,
        'Voltage Phasor (Magnitude, Angle)': voltage_phasor,
        'Current Phasor (Magnitude, Angle)': current_phasor
    }

if __name__ == "__main__":
    # Generate a random 32-byte key for AES-256
    key = os.urandom(AES_KEY_SIZE)
    
    # Create GOOSE PDU
    pdu = create_goose_pdu()
    print("GOOSE PDU (Binary):", pdu)
    
    # Encrypt the GOOSE PDU
    encrypted_pdu = encrypt_aes_gcm(pdu, key)
    print("Encrypted GOOSE PDU:", encrypted_pdu)
    
    # Decrypt the GOOSE PDU
    decrypted_pdu = decrypt_aes_gcm(encrypted_pdu, key)
    
    # Decode the GOOSE PDU
    decoded_data = decode_goose_pdu(decrypted_pdu)
    print("Decoded GOOSE PDU Data:")
    for key, value in decoded_data.items():
        print(f"{key}: {value}")
