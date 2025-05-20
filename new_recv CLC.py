from datetime import datetime
import socket
import struct
import sys
from dataclasses import dataclass
import time
import netifaces
import os

from compression_encryption import decrypt_aes_gcm, decompress_data, encrypt_aes_gcm
from ied_utils import getIPv4Add
from parse_sed import parse_sed
from compression_encryption import key
from compression_encryption import generate_hmac_cryptography

@dataclass
class ReceivedPacket:
    packet_type: str
    appid: int
    length: int
    timestamp: float
    multicast_ip: str
    
    # GOOSE specific fields
    gocb_ref: str = None
    time_allowed_to_live: int = None
    dat_set: str = None
    go_id: str = None
    st_num: int = None
    sq_num: int = None
    test: bool = None
    conf_rev: int = None
    nds_com: bool = None
    num_dat_set_entries: int = None
    data_values: list = None
    
    # SV specific fields
    svid: str = None
    smp_cnt: int = None
    smp_synch: int = None
    sample_data: list = None

def join_multicast_group(sock, multicast_ip, interface_name):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    if interface_name not in netifaces.interfaces():
        print(f"Interface {interface_name} not found!")
        sys.exit(1)
    
    addrs = netifaces.ifaddresses(interface_name)
    if netifaces.AF_INET not in addrs:
        print(f"No IPv4 address found for interface {interface_name}")
        sys.exit(1)
        
    addr = addrs[netifaces.AF_INET][0]['addr']
    
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, 
                    socket.inet_aton(addr))
    
    mreq = struct.pack('4s4s', socket.inet_aton(multicast_ip),
                      socket.inet_aton(addr))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

def decode_asn1_length(data, offset):
    if offset >= len(data):
        return 0, offset
    
    length = data[offset]
    new_offset = offset + 1
    
    if length & 0x80:
        length_bytes = length & 0x7F
        if new_offset + length_bytes > len(data):
            return 0, offset
        length = 0
        for i in range(length_bytes):
            length = (length << 8) | data[new_offset]
            new_offset += 1
    return length, new_offset

def safe_get_bytes(data, start, length):
    if start + length > len(data):
        return None
    return data[start:start + length]

def decode_goose_pdu(data, offset):
    try:
        packet = ReceivedPacket(packet_type='GOOSE', 
                               appid=0, length=0, 
                               timestamp=time.time(),
                               multicast_ip='')
        
        if offset >= len(data):
            return packet
            
        pdu_len, offset = decode_asn1_length(data, offset + 1)
        
        while offset < len(data):
            tag = data[offset]
            offset += 1
            length, offset = decode_asn1_length(data, offset)
            
            if offset + length > len(data):
                break
                
            if tag == 0x80:
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.gocb_ref = bytes_data.decode('utf-8', errors='ignore')
            elif tag == 0x81:
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.time_allowed_to_live = int.from_bytes(bytes_data, 'big')
            elif tag == 0x82:
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.dat_set = bytes_data.decode('utf-8', errors='ignore')
            elif tag == 0x83:
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.go_id = bytes_data.decode('utf-8', errors='ignore')
            elif tag == 0x84:
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data and len(bytes_data) == 8:
                    packet.timestamp = struct.unpack('>d', bytes_data)[0]
            elif tag == 0x85:
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.st_num = int.from_bytes(bytes_data, 'big')
            elif tag == 0x86:
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.sq_num = int.from_bytes(bytes_data, 'big')
            elif tag == 0x87:
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    packet.test = bool(bytes_data[0])
            elif tag == 0x88:
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.conf_rev = int.from_bytes(bytes_data, 'big')
            elif tag == 0x89:
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    packet.nds_com = bool(bytes_data[0])
            elif tag == 0x8A:
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    packet.num_dat_set_entries = bytes_data[0]
            elif tag == 0xAB:
                packet.data_values = []
                data_offset = offset
                while data_offset < offset + length and data_offset < len(data):
                    value_tag = data[data_offset]
                    data_offset += 1
                    value_len, data_offset = decode_asn1_length(data, data_offset)
                    if value_tag == 0x83 and data_offset < len(data):
                        packet.data_values.append(bool(data[data_offset]))
                    data_offset += value_len
            
            offset += length
        
        return packet
    except Exception as e:
        print(f"Error decoding GOOSE PDU: {e}")
        return None

def decode_sv_pdu(data, offset):
    try:
        packet = ReceivedPacket(packet_type='SV',
                               appid=0, length=0,
                               timestamp=time.time(),
                               multicast_ip='')
        
        if offset >= len(data):
            return packet
            
        pdu_len, offset = decode_asn1_length(data, offset + 1)
        
        while offset < len(data):
            tag = data[offset]
            offset += 1
            length, offset = decode_asn1_length(data, offset)
            
            if offset + length > len(data):
                break
                
            if tag == 0x80:
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    no_asdu = bytes_data[0]
            elif tag == 0xA2:
                asdu_offset = offset
                while asdu_offset < offset + length and asdu_offset < len(data):
                    if data[asdu_offset] == 0x30:
                        asdu_len, asdu_offset = decode_asn1_length(data, asdu_offset + 1)
                        inner_offset = asdu_offset
                        
                        while inner_offset < asdu_offset + asdu_len and inner_offset < len(data):
                            inner_tag = data[inner_offset]
                            inner_offset += 1
                            inner_len, inner_offset = decode_asn1_length(data, inner_offset)
                            
                            if inner_offset + inner_len > len(data):
                                break
                                
                            if inner_tag == 0x80:
                                bytes_data = safe_get_bytes(data, inner_offset, inner_len)
                                if bytes_data:
                                    packet.svid = bytes_data.decode('utf-8', errors='ignore')
                            elif inner_tag == 0x82:
                                bytes_data = safe_get_bytes(data, inner_offset, inner_len)
                                if bytes_data:
                                    packet.smp_cnt = int.from_bytes(bytes_data, 'big')
                            elif inner_tag == 0x85:
                                bytes_data = safe_get_bytes(data, inner_offset, 1)
                                if bytes_data:
                                    packet.smp_synch = bytes_data[0]
                            elif inner_tag == 0x87:
                                packet.sample_data = []
                                sample_offset = inner_offset
                                while sample_offset + 4 <= inner_offset + inner_len:
                                    bytes_data = safe_get_bytes(data, sample_offset, 4)
                                    if bytes_data:
                                        value = struct.unpack('>f', bytes_data)[0]
                                        packet.sample_data.append(value)
                                    sample_offset += 4
                            elif inner_tag == 0x89:
                                bytes_data = safe_get_bytes(data, inner_offset, inner_len)
                                if bytes_data and len(bytes_data) == 8:
                                    packet.timestamp = struct.unpack('>d', bytes_data)[0]
                            
                            inner_offset += inner_len
                        
                        asdu_offset += asdu_len
                    else:
                        asdu_offset += 1
            
            offset += length
        
        return packet
    except Exception as e:
        print(f"Error decoding SV PDU: {e}")
        return None

total_transmission_time_goose = 0.0
total_packets_goose = 0
total_transmission_time_sv = 0.0
total_packets_sv = 0
total_decrypt_time = 0.0
total_packets = 0

def display_packet_info(packet):
    if not packet:
        return
        
    print("\n" + "="*80)
    print(f"Received {packet.packet_type} Packet from {packet.multicast_ip}")
    
    print(f"Packet Timestamp: {datetime.fromtimestamp(packet.timestamp)}")

    current_datetime = time.time()
    print("Current Timestamp", datetime.fromtimestamp(current_datetime))
    time_difference_ms = (current_datetime - packet.timestamp) * 1000

    print("Transmission time: ", round(time_difference_ms, 6), " ms")
    
    print(f"APPID: 0x{packet.appid:04x}")
    print(f"Length: {packet.length} bytes")
    
    if packet.packet_type == 'GOOSE':
        global total_transmission_time_goose, total_packets_goose        
        total_packets_goose += 1
        total_transmission_time_goose += time_difference_ms
        print("Average Goose Transmission time: ", total_transmission_time_goose/total_packets_goose)

        print("\nGOOSE Specific Information:")
        if packet.gocb_ref: print(f"GoCB Reference: {packet.gocb_ref}")
        if packet.time_allowed_to_live: print(f"Time Allowed to Live: {packet.time_allowed_to_live}ms")
        if packet.dat_set: print(f"Dataset: {packet.dat_set}")
        if packet.go_id: print(f"GoID: {packet.go_id}")
        if packet.st_num is not None: print(f"StNum: {packet.st_num}")
        if packet.sq_num is not None: print(f"SqNum: {packet.sq_num}")
        if packet.test is not None: print(f"Test: {packet.test}")
        if packet.conf_rev is not None: print(f"ConfRev: {packet.conf_rev}")
        if packet.nds_com is not None: print(f"NdsCom: {packet.nds_com}")
        if packet.num_dat_set_entries is not None: print(f"Number of Dataset Entries: {packet.num_dat_set_entries}")
        if packet.data_values: print(f"Data Values: {packet.data_values}")
    
    elif packet.packet_type == 'SV':
        global total_transmission_time_sv, total_packets_sv
        total_packets_sv += 1
        total_transmission_time_sv += time_difference_ms
        print("Average SV Transmission time: ", total_transmission_time_sv/total_packets_sv)

        print("\nSampled Values Specific Information:")
        if packet.svid: print(f"svID: {packet.svid}")
        if packet.smp_cnt is not None: print(f"Sample Count: {packet.smp_cnt}")
        if packet.smp_synch is not None: print(f"Sample Sync: {packet.smp_synch}")
        if packet.sample_data:
            print("\nSample Values:")
            for i, value in enumerate(packet.sample_data):
                print(f"  Sample {i}: {value}")

# ied_recv.py# ied_recv.py
import sys
import socket
import struct
import time
import pickle
from typing import List

from ied_utils import getIPv4Add
from parse_sed import parse_sed
from certificateless_crypto import CLUser, KGC, deserialize_encrypted_data, deserialize_signature

# Constants
IEDUDPPORT = 102
NAMESPACE = '{http://www.iec.ch/61850/2003/SCL}'

# Decryption timing trackers
total_decrypt_time = 0
total_packets = 0

# Store users by IED name
ied_users = {}

def initialize_crypto_for_ied(ied_name, kgc_params, kgc):
    """Initialize a certificateless user for the IED"""
    if ied_name in ied_users:
        return ied_users[ied_name]
    
    # Create a user with the IED's identity
    user = CLUser(ied_name, kgc_params)
    
    # Generate partial private key from KGC
    partial_key = kgc.extract_partial_private_key(ied_name)
    user.set_partial_private_key(partial_key)
    
    ied_users[ied_name] = user
    return user

def process_packet(data: bytes, addr: tuple, local_ied_name: str):
    """Process and decrypt received packet"""
    global total_decrypt_time, total_packets
    
    try:
        # Print raw data for debugging
        print(f"First 64 bytes of received data: {data[:64].hex()}")
        
        # Basic header validation
        if len(data) < 30:  # Minimum expected header size
            print("Packet too small")
            return None
        
        # Parse the packet structure as defined in ied_send.py
        offset = 0
        
        # Print header fields for debugging
        print(f"Header bytes: {data[:6].hex()}")
        
        # OSI UDP headers and session header
        offset += 4  # Skip first 4 bytes (OSI UDP + session headers)
        
        # Parameter ID + length
        param_id = data[offset]
        param_len = data[offset+1]
        print(f"Parameter ID: 0x{param_id:02x}, Length: 0x{param_len:02x}")
        
        if param_id != 0x80 or param_len != 0x16:
            print(f"Invalid parameter header - expected 0x80 0x16, got 0x{param_id:02x} 0x{param_len:02x}")
            return None
        offset += 2
        
        # SPDU length and number
        try:
            spdu_length = struct.unpack('>I', data[offset:offset+4])[0]
            print(f"SPDU Length: {spdu_length}")
            offset += 4
            
            spdu_num = struct.unpack('>I', data[offset:offset+4])[0]
            print(f"SPDU Number: {spdu_num}")
            offset += 4
        except struct.error as e:
            print(f"Error unpacking SPDU length/number: {e}")
            return None
        
        # Version
        try:
            version = struct.unpack('>H', data[offset:offset+2])[0]
            print(f"Protocol Version: {version}")
            if version != 2:  # Updated for CL crypto
                print(f"Unsupported protocol version: {version}")
                return None
            offset += 2
        except struct.error as e:
            print(f"Error unpacking version: {e}")
            return None
        
        # Timestamp
        try:
            timestamp = struct.unpack('>I', data[offset:offset+4])[0]
            print(f"Timestamp: {timestamp}")
            offset += 4
        except struct.error as e:
            print(f"Error unpacking timestamp: {e}")
            return None
        
        # Sender identity (16 bytes)
        try:
            sender_id_bytes = data[offset:offset+16]
            sender_id = sender_id_bytes.rstrip(b'\0').decode('utf-8')
            print(f"Sender ID: {sender_id}")
            offset += 16
        except Exception as e:
            print(f"Error decoding sender ID: {e}")
            return None
        
        # Get encrypted data length and data
        try:
            if offset + 4 > len(data):
                print(f"Packet too short for encrypted data length field at offset {offset}")
                return None
                
            enc_data_len = struct.unpack('>I', data[offset:offset+4])[0]
            print(f"Encrypted data length: {enc_data_len}")
            offset += 4
            
            if offset + enc_data_len > len(data):
                print(f"Packet too short for encrypted data: expected {enc_data_len} bytes at offset {offset}, have {len(data) - offset}")
                return None
                
            serialized_enc_data = data[offset:offset+enc_data_len]
            print(f"Serialized encrypted data size: {len(serialized_enc_data)}")
            try:
                encrypted_data = deserialize_encrypted_data(pickle.loads(serialized_enc_data))
                print(f"Deserialized encrypted data: {type(encrypted_data)}")
                print(f"Keys: {encrypted_data.keys()}")
            except Exception as e:
                print(f"Error deserializing encrypted data: {e}")
                print(f"First 20 bytes of serialized data: {serialized_enc_data[:20].hex()}")
                return None
            offset += enc_data_len
        except struct.error as e:
            print(f"Error unpacking encrypted data length: {e}")
            return None
        
        # Get signature length and data
        try:
            if offset + 4 > len(data):
                print(f"Packet too short for signature length field at offset {offset}")
                return None
                
            sig_len = struct.unpack('>I', data[offset:offset+4])[0]
            print(f"Signature length: {sig_len}")
            offset += 4
            
            if offset + sig_len > len(data):
                print(f"Packet too short for signature: expected {sig_len} bytes at offset {offset}, have {len(data) - offset}")
                return None
                
            serialized_signature = data[offset:offset+sig_len]
            try:
                signature = deserialize_signature(pickle.loads(serialized_signature))
                print(f"Deserialized signature: {type(signature)}")
                print(f"Keys: {signature.keys()}")
            except Exception as e:
                print(f"Error deserializing signature: {e}")
                return None
            offset += sig_len
        except struct.error as e:
            print(f"Error unpacking signature length: {e}")
            return None
        
        # Get KGC public key
        try:
            if offset + 4 > len(data):
                print(f"Packet too short for KGC key length field at offset {offset}")
                return None
                
            kgc_key_len = struct.unpack('>I', data[offset:offset+4])[0]
            print(f"KGC public key length: {kgc_key_len}")
            offset += 4
            
            if offset + kgc_key_len > len(data):
                print(f"Packet too short for KGC key: expected {kgc_key_len} bytes at offset {offset}, have {len(data) - offset}")
                return None
                
            kgc_public_key = data[offset:offset+kgc_key_len]
            print(f"KGC public key size: {len(kgc_public_key)}")
        except struct.error as e:
            print(f"Error unpacking KGC key length: {e}")
            return None
        
        # Get or initialize KGC
        kgc = None
        if local_ied_name not in ied_users:
            print(f"Initializing new KGC and user for local IED: {local_ied_name}")
            # First time seeing this KGC key, create a new KGC
            kgc = KGC()
            kgc_params = kgc.get_public_params()
            # Initialize local IED user
            initialize_crypto_for_ied(local_ied_name, kgc_params, kgc)
        
        # Initialize sender IED user if not already done
        if sender_id not in ied_users:
            print(f"Initializing user for sender IED: {sender_id}")
            if not kgc:
                # Get KGC from existing user
                kgc_params = list(ied_users.values())[0].params
                kgc = KGC()  # Creating a new KGC instance
                kgc_params.kgc_pub_key = kgc_public_key  # Setting received public key
            else:
                kgc_params = kgc.get_public_params()
            
            sender_user = CLUser(sender_id, kgc_params)
            partial_key = kgc.extract_partial_private_key(sender_id)
            sender_user.set_partial_private_key(partial_key)
            ied_users[sender_id] = sender_user
        
        # Decrypt the message
        local_user = ied_users[local_ied_name]
        
        start_time = time.time() * 1000
        
        # Get the sender's user
        sender_user = ied_users[sender_id]
        
        # Decrypt the message
        try:
            print(f"Attempting to decrypt message from {sender_id} to {local_ied_name}")
            plaintext = local_user.decrypt("broadcast", encrypted_data)
            print(f"Decryption successful, plaintext size: {len(plaintext)}")
        except Exception as e:
            import traceback
            print(f"Decryption error: {e}")
            traceback.print_exc()
            return None
        
        # Verify the signature
        try:
            print("Verifying signature...")
            verified = local_user.verify(
                sender_id, 
                sender_user.get_user_public_key_bytes(),
                plaintext,
                signature,
                kgc_public_key
            )
            
            if not verified:
                print("Signature verification failed")
                return None
            else:
                print("Signature verification successful")
        except Exception as e:
            print(f"Signature verification error: {e}")
            return None
        
        end_time = time.time() * 1000
        decrypt_time = end_time - start_time
        
        total_decrypt_time += decrypt_time
        total_packets += 1
        
        print(f"Packet #{total_packets}: CL-Decrypt took {round(decrypt_time, 3)} ms")
        print(f"Avg Time: {round(total_decrypt_time / total_packets, 3)} ms")
        
        # Process the decrypted payload
        try:
            print(f"Decrypted payload first few bytes: {plaintext[:10].hex()}")
            payload_type = plaintext[0]
            simulation = plaintext[1]
            appid = (plaintext[2] << 8) | plaintext[3]
            length = (plaintext[4] << 8) | plaintext[5]
            
            print(f"Payload type: 0x{payload_type:02x}, Simulation: {simulation}, AppID: 0x{appid:04x}, Length: {length}")
            
            packet = None
            if payload_type == 0x81:  # GOOSE
                print("Processing GOOSE PDU")
                packet = decode_goose_pdu(plaintext, 6)
            elif payload_type == 0x82:  # SV
                print("Processing SV PDU")
                packet = decode_sv_pdu(plaintext, 6)
            else:
                print(f"Unknown payload type: 0x{payload_type:02x}")
            
            if packet:
                packet.appid = appid
                packet.length = length
                packet.multicast_ip = addr[0]
                packet.sender_id = sender_id
                packet.spdu_num = spdu_num
                packet.timestamp = timestamp
                display_packet_info(packet)
                
            return packet
            
        except Exception as e:
            print(f"Error processing decrypted payload: {e}")
            import traceback
            traceback.print_exc()
            return None
        
    except Exception as e:
        print(f"Packet processing error: {e}")
        import traceback
        traceback.print_exc()
        return None
    
def main():
    if len(sys.argv) != 4:
        if sys.argv[0]:
            print(f"Usage: {sys.argv[0]} <SED Filename> <Interface Name to be used on IED> <IED Name>")
        else:
            print("Usage: <program name> <SED Filename> <Interface Name to be used on IED> <IED Name>")
        return 1

    sed_filename = sys.argv[1]
    interface_name = sys.argv[2]
    ied_name = sys.argv[3]

    # Setup KGC for this IED
    kgc = KGC()
    kgc_params = kgc.get_public_params()
    initialize_crypto_for_ied(ied_name, kgc_params, kgc)

    # Parse SED file to find relevant multicast IPs
    vector_of_ctrl_blks = parse_sed(sed_filename)
    multicast_ips = set()
    
    # Collect all multicast IPs from control blocks
    for cb in vector_of_ctrl_blks:
        if cb.multicastIP:
            multicast_ips.add(cb.multicastIP)
            print(f"Found multicast IP: {cb.multicastIP} for control block {cb.cbName}")
    
    if not multicast_ips:
        print(f"No multicast IPs found in the SED file")
        return 1

    # Create socket and join multicast groups
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Bind to IED port
        sock.bind(('', IEDUDPPORT))
        
        # Join each multicast group
        for multicast_ip in multicast_ips:
            join_multicast_group(sock, multicast_ip, interface_name)
            print(f"Joined multicast group: {multicast_ip}")
        
        print(f"Listening for RGOOSE/RSV packets on {interface_name} (multicast groups)...")
        
        while True:
            data, addr = sock.recvfrom(65535)
            print(f"\nReceived packet from {addr[0]}:{addr[1]}, size: {len(data)} bytes")
            print("-" * 80)
            
            process_packet(data, addr, ied_name)
                
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        sock.close()


if __name__ == "__main__":
    main()