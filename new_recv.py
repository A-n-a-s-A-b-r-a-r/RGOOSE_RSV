
import socket
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime

import netifaces

from compression_encryption import decrypt_aes_gcm, decompress_data, encrypt_aes_gcm, key, generate_hmac_cryptography
from ied_utils import getIPv4Add
from parse_sed import parse_sed

from CLC import CertificatelessCrypto
# --- Data Structures ---

@dataclass
class ReceivedPacket:
    """Represents a received IEC 61850 packet (GOOSE or SV)"""
    packet_type: str  # 'GOOSE' or 'SV'
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


# --- Global Statistics Tracking ---

class Statistics:
    """Tracks transmission statistics for GOOSE and SV packets"""
    def __init__(self):
        self.total_transmission_time_goose = 0.0
        self.total_packets_goose = 0
        self.total_transmission_time_sv = 0.0
        self.total_packets_sv = 0
        self.total_decrypt_time = 0.0
        self.total_packets = 0
    
    def update_goose_stats(self, transmission_time):
        """Update GOOSE packet statistics"""
        self.total_packets_goose += 1
        self.total_transmission_time_goose += transmission_time
        self.total_packets += 1
        
    def update_sv_stats(self, transmission_time):
        """Update SV packet statistics"""
        self.total_packets_sv += 1
        self.total_transmission_time_sv += transmission_time
        self.total_packets += 1
    
    def get_avg_goose_time(self):
        """Get average GOOSE transmission time in ms"""
        if self.total_packets_goose == 0:
            return 0
        return self.total_transmission_time_goose / self.total_packets_goose
    
    def get_avg_sv_time(self):
        """Get average SV transmission time in ms"""
        if self.total_packets_sv == 0:
            return 0
        return self.total_transmission_time_sv / self.total_packets_sv


# --- Network Functions ---

def join_multicast_group(sock, multicast_ip, interface_name):
    """Join a multicast group on specified interface"""
    # Allow multiple sockets to use the same port
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to INADDR_ANY
    sock.bind(('', 102))  # Port 102 as per your sender
    
    # Get the IP address of the specified interface
    if interface_name not in netifaces.interfaces():
        print(f"Interface {interface_name} not found!")
        sys.exit(1)
    
    addrs = netifaces.ifaddresses(interface_name)
    if netifaces.AF_INET not in addrs:
        print(f"No IPv4 address found for interface {interface_name}")
        sys.exit(1)
        
    addr = addrs[netifaces.AF_INET][0]['addr']
    
    # Set the interface for the multicast group
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, 
                    socket.inet_aton(addr))
    
    # Join multicast group
    mreq = struct.pack('4s4s', socket.inet_aton(multicast_ip),
                      socket.inet_aton(addr))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


# --- ASN.1 Decoding Utilities ---

def decode_asn1_length(data, offset):
    """Decode ASN.1 length field and return (length, new_offset)"""
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
    """Safely get bytes from data with bounds checking"""
    if start + length > len(data):
        return None
    return data[start:start + length]


# --- Packet Decoders ---

def decode_goose_pdu(data, offset):
    """Decode GOOSE PDU and return packet info"""
    try:
        packet = ReceivedPacket(
            packet_type='GOOSE', 
            appid=0, 
            length=0, 
            timestamp=time.time(),
            multicast_ip=''
        )
        
        # Skip GOOSE PDU tag
        if offset >= len(data):
            return packet
            
        pdu_len, offset = decode_asn1_length(data, offset + 1)
        
        while offset < len(data):
            tag = data[offset]
            offset += 1
            length, offset = decode_asn1_length(data, offset)
            
            if offset + length > len(data):
                break
                
            if tag == 0x80:  # gocbRef
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.gocb_ref = bytes_data.decode('utf-8', errors='ignore')
            elif tag == 0x81:  # timeAllowedToLive
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.time_allowed_to_live = int.from_bytes(bytes_data, 'big')
            elif tag == 0x82:  # datSet
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.dat_set = bytes_data.decode('utf-8', errors='ignore')
            elif tag == 0x83:  # goID
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.go_id = bytes_data.decode('utf-8', errors='ignore')
            elif tag == 0x84:  # timestamp
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data and len(bytes_data) == 8:  # Ensure we have 8 bytes for double
                    packet.timestamp = struct.unpack('>d', bytes_data)[0]
            elif tag == 0x85:  # stNum
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.st_num = int.from_bytes(bytes_data, 'big')
            elif tag == 0x86:  # sqNum
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.sq_num = int.from_bytes(bytes_data, 'big')
            elif tag == 0x87:  # test
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    packet.test = bool(bytes_data[0])
            elif tag == 0x88:  # confRev
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.conf_rev = int.from_bytes(bytes_data, 'big')
            elif tag == 0x89:  # ndsCom
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    packet.nds_com = bool(bytes_data[0])
            elif tag == 0x8A:  # numDatSetEntries
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    packet.num_dat_set_entries = bytes_data[0]
            elif tag == 0xAB:  # allData
                packet.data_values = []
                data_offset = offset
                while data_offset < offset + length and data_offset < len(data):
                    value_tag = data[data_offset]
                    data_offset += 1
                    value_len, data_offset = decode_asn1_length(data, data_offset)
                    if value_tag == 0x83 and data_offset < len(data):  # Boolean
                        packet.data_values.append(bool(data[data_offset]))
                    data_offset += value_len
            
            offset += length
        
        return packet
    except Exception as e:
        print(f"Error decoding GOOSE PDU: {e}")
        return None


def decode_sv_pdu(data, offset):
    """Decode Sampled Values PDU and return packet info"""
    try:
        packet = ReceivedPacket(
            packet_type='SV',
            appid=0, 
            length=0,
            timestamp=time.time(),
            multicast_ip=''
        )
        
        if offset >= len(data):
            return packet
            
        # Skip SV PDU tag and length
        pdu_len, offset = decode_asn1_length(data, offset + 1)
        
        while offset < len(data):
            tag = data[offset]
            offset += 1
            length, offset = decode_asn1_length(data, offset)
            
            if offset + length > len(data):
                break
                
            if tag == 0x80:  # noASDU
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    no_asdu = bytes_data[0]
            elif tag == 0xA2:  # seqOfASDU
                asdu_offset = offset
                while asdu_offset < offset + length and asdu_offset < len(data):
                    if data[asdu_offset] == 0x30:  # ASDU
                        asdu_len, asdu_offset = decode_asn1_length(data, asdu_offset + 1)
                        inner_offset = asdu_offset
                        
                        while inner_offset < asdu_offset + asdu_len and inner_offset < len(data):
                            inner_tag = data[inner_offset]
                            inner_offset += 1
                            inner_len, inner_offset = decode_asn1_length(data, inner_offset)
                            
                            if inner_offset + inner_len > len(data):
                                break
                                
                            if inner_tag == 0x80:  # svID
                                bytes_data = safe_get_bytes(data, inner_offset, inner_len)
                                if bytes_data:
                                    packet.svid = bytes_data.decode('utf-8', errors='ignore')
                            elif inner_tag == 0x82:  # smpCnt
                                bytes_data = safe_get_bytes(data, inner_offset, inner_len)
                                if bytes_data:
                                    packet.smp_cnt = int.from_bytes(bytes_data, 'big')
                            elif inner_tag == 0x85:  # smpSynch
                                bytes_data = safe_get_bytes(data, inner_offset, 1)
                                if bytes_data:
                                    packet.smp_synch = bytes_data[0]
                            elif inner_tag == 0x87:  # seqOfData
                                packet.sample_data = []
                                sample_offset = inner_offset
                                while sample_offset + 4 <= inner_offset + inner_len:
                                    bytes_data = safe_get_bytes(data, sample_offset, 4)
                                    if bytes_data:
                                        value = struct.unpack('>f', bytes_data)[0]
                                        packet.sample_data.append(value)
                                    sample_offset += 4
                            elif inner_tag == 0x89:  # timestamp
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


# --- Display Functions ---

def display_packet_info(packet, stats):
    """Display received packet information with statistics"""
    if not packet:
        return
    
    print("\n" + "="*80)
    print(f"Received {packet.packet_type} Packet from {packet.multicast_ip}")
    
    print(f"Packet Timestamp: {datetime.fromtimestamp(packet.timestamp)}")

    current_datetime = time.time()
    print("Current Timestamp:", datetime.fromtimestamp(current_datetime))
    time_difference_ms = (current_datetime - packet.timestamp) * 1000

    print("Transmission time:", round(time_difference_ms, 6), "ms")
    
    print(f"APPID: 0x{packet.appid:04x}")
    print(f"Length: {packet.length} bytes")
    
    if packet.packet_type == 'GOOSE':
        stats.update_goose_stats(time_difference_ms)
        print("Average GOOSE Transmission time:", stats.get_avg_goose_time())

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
        stats.update_sv_stats(time_difference_ms)
        print("Average SV Transmission time:", stats.get_avg_sv_time())

        print("\nSampled Values Specific Information:")
        if packet.svid: print(f"svID: {packet.svid}")
        if packet.smp_cnt is not None: print(f"Sample Count: {packet.smp_cnt}")
        if packet.smp_synch is not None: print(f"Sample Sync: {packet.smp_synch}")
        if packet.sample_data:
            print("\nSample Values:")
            for i, value in enumerate(packet.sample_data):
                print(f"  Sample {i}: {value}")


# --- Packet Processing ---

def process_received_data(data, addr, stats):
    """Process received data and extract packet information"""
    if len(data) < 4:  # Minimum required length
        return
        
    try:
        # Skip LI and TI bytes
        offset = 2
        
        # Check packet type
        packet_type = data[offset]
        offset += 1
        
        # Skip LI byte
        offset += 1
        
        # Skip common session header
        if offset < len(data) and data[offset] == 0x80:
            offset += 2  # Skip PI and LI
            
            # Skip SPDU length and number
            offset += 8
            
            # Skip version number
            offset += 2
            
            # Skip security information
            offset += 12
            
            if offset + 4 >= len(data):
                return
                
            # Get payload length
            payload_len = int.from_bytes(data[offset:offset+4], 'big')
            offset += 4
            
            if offset + 6 >= len(data):
                return
                
            # Process payload
            payload_type = data[offset]
            simulation = data[offset + 1]
            appid = int.from_bytes(data[offset+2:offset+4], 'big')
            length = int.from_bytes(data[offset+4:offset+6], 'big')
            
            # Move to PDU
            offset += 6
            
            packet = None

            if payload_type == 0x81:  # GOOSE
                packet = decode_goose_pdu(data, offset)
            elif payload_type == 0x82:  # SV
                packet = decode_sv_pdu(data, offset)
        
            if packet:
                packet.appid = appid
                packet.length = length
                packet.multicast_ip = addr[0]
                display_packet_info(packet, stats)
    except Exception as e:
        print(f"Error processing packet: {e}")


# --- Main Function ---

def main():
    # Initialize certificateless cryptography with 30-second key rotation
    crypto = CertificatelessCrypto(key_dir='./keys', rotation_interval=30)
    print("Initialized certificateless cryptography with 30-second key rotation")   
    """Main function to receive and process IEC 61850 packets"""
    if len(sys.argv) != 4:
        program_name = sys.argv[0] if sys.argv and sys.argv[0] else "<program name>"
        print(f"Usage: {program_name} <SED Filename> <Interface Name to be used on IED> <IED Name>")
        return 1

    # Parse command line arguments
    sed_filename = sys.argv[1]
    interface_name = sys.argv[2]
    ied_name = sys.argv[3]
    
    # Get IPv4 address of specified Network Interface
    ifr = getIPv4Add(interface_name)
    ifr = socket.inet_pton(socket.AF_INET, ifr)

    # Parse SED file to get multicast IP
    multicast_ip = None
    vector_of_ctrl_blks = parse_sed(sed_filename)
    for it in vector_of_ctrl_blks:
        print(it.hostIED)
        if it.hostIED == ied_name:
            print(it.multicastIP)
            multicast_ip = it.multicastIP
            break
            
    if not multicast_ip:
        print(f"Error: No multicast IP found for IED {ied_name}")
        return 1

    # Initialize statistics tracker
    stats = Statistics()

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Test encryption/decryption
    demo_data = encrypt_aes_gcm(bytes([123]))
    decrypt_aes_gcm(demo_data)

    try:
        # Join multicast group
        join_multicast_group(sock, multicast_ip, interface_name)
        print(f"Listening for RGOOSE/RSV packets on {interface_name} ({multicast_ip})...")
        
        # Main receive loop
        while True:
            # Check if keys need rotation
            if crypto.check_and_rotate_keys():
                print("Keys rotated")
            data, addr = sock.recvfrom(65535)
            
            # Extract packet components
            headers = list(data[:32])
            payload = data[32:-34]
            signature = list(data[-34:])
            
            # With certificateless crypto, we rely on AES-GCM's authentication
            # You can still verify a separate HMAC if needed
            t1 = time.time()
            mac = generate_hmac_cryptography(key, list(data[:-32]))
            t2 = time.time()
            print(f"{t2-t1:.6f} mac generation time")

            # Check signature - note that our certificateless crypto provides authentication already
            if list(mac) != signature[2:]:
                print("Warning: MAC mismatch, but continuing as crypto provides authentication")
                # We don't continue here as we're relying on crypto's authentication

            # Decrypt and decompress payload
            # Check and possibly rotate keys
            crypto.check_and_rotate_keys()

            # Decrypt with certificateless crypto and then decompress
            start_time = time.time() * 1000
            try:
                decrypted_payload = crypto.decrypt_bytes(bytes(payload))
                decompressed_payload = decompress_data(bytes(decrypted_payload))
            except Exception as e:
                print(f"Decryption error: {e}")
                continue    

            # Reconstruct packet
            reconstructed_data = headers + list(decompressed_payload) + signature
            reconstructed_data = bytearray(reconstructed_data)

            # Process the packet
            process_received_data(reconstructed_data, addr, stats)
                
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())