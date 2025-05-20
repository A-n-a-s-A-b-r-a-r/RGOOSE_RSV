# ied_send.py
import sys
import socket
import struct
import time
import os
import pickle

from ied_utils import *
from udpSock import UdpSock
from zz_diagnose import diagnose
from parse_sed import parse_sed
from form_pdu import form_goose_pdu, form_sv_pdu
from certificateless_crypto import KGC, CLUser, serialize_encrypted_data, serialize_signature

# Constants
IEDUDPPORT = 102
NAMESPACE = '{http://www.iec.ch/61850/2003/SCL}'

# Encryption timing trackers
total_encrypt_time = 0
total_packets = 0

# Certificateless cryptography setup
kgc = KGC()
kgc_params = kgc.get_public_params()
kgc_public_key = kgc.get_kgc_public_key_bytes()

# Store users by IED name
ied_users = {}

def parse_arguments(argv):
    if len(argv) != 4:
        print(f"Usage: {argv[0]} <SED Filename> <Interface Name> <IED Name>")
        sys.exit(1)
    return argv[1], argv[2], argv[3] 

def initialize_crypto_for_ied(ied_name):
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

def initialize_control_blocks(sed_file, ied_name):
    control_blocks = parse_sed(sed_file)
    own_blocks = []
    goose_counter, sv_counter = 0, 0

    # Initialize crypto for this IED
    ied_user = initialize_crypto_for_ied(ied_name)

    for cb in control_blocks:
        if cb.hostIED != ied_name:
            # Initialize crypto for other IEDs for communication
            initialize_crypto_for_ied(cb.hostIED)
            continue

        tmp_data = GooseSvData()
        tmp_data.cbName = cb.cbName
        tmp_data.cbType = cb.cbType
        tmp_data.appID = cb.appID
        tmp_data.multicastIP = cb.multicastIP
        tmp_data.prev_spduNum = 0  # Initialize SPDU counter

        if cb.cbType == f'{NAMESPACE}GSE':
            goose_counter += 1
            tmp_data.datSetName = cb.datSetName
            tmp_data.goose_counter = goose_counter
        elif cb.cbType == f'{NAMESPACE}SMV':
            sv_counter += 1
            tmp_data.sv_counter = sv_counter

        own_blocks.append(tmp_data)

    return own_blocks

def build_udp_packet(block, s_value, sender_ied):
    sender_user = ied_users[sender_ied]
    payload = []
    pdu = []

    if block.cbType == f"{NAMESPACE}GSE":
        form_goose_pdu(block, pdu)
        payload.append(0x81)  # GOOSE payload ID
    elif block.cbType == f"{NAMESPACE}SMV":
        form_sv_pdu(block, pdu)
        payload.append(0x82)  # SV payload ID

    payload += [
        0x00,  # Simulation: false
        (int(block.appID, 16) >> 8) & 0xFF,
        int(block.appID, 16) & 0xFF
    ]

    apdu_len = len(pdu) + 2
    payload += [(apdu_len >> 8) & 0xFF, apdu_len & 0xFF]
    payload.extend(pdu)

    # Convert payload to bytes
    payload_bytes = bytes(payload)

    # Encrypt using certificateless crypto
    global total_encrypt_time, total_packets
    start_time = time.time() * 1000
    
    # For broadcasting, we encrypt with a sender key that can be verified by any receiver
    encrypted_data = sender_user.encrypt(
        "broadcast", # Recipient is the same as sender for broadcast
        sender_user.get_user_public_key_bytes(),
        payload_bytes
    )
    
    # Sign the payload with certificateless signature
    signature = sender_user.sign(payload_bytes)
    
    encrypt_time = time.time() * 1000 - start_time
    total_encrypt_time += encrypt_time
    total_packets += 1

    print(f"Packet #{total_packets}: CL-Encrypt took {round(encrypt_time, 3)} ms")
    print(f"Avg Time: {round(total_encrypt_time / total_packets, 3)} ms")

    # Prepare UDP packet structure
    udp_data = [
        0x01, 0x40,  # OSI UDP headers
        0xA1 if block.cbType == f"{NAMESPACE}GSE" else 0xA2,
        0x18,  # session header
        0x80, 0x16  # parameter ID + length
    ]

    # Add SPDU header
    spdu_length = 4 + 2 + 12 + 4 + len(encrypted_data['ciphertext']) + 2
    udp_data += list(struct.pack('>I', spdu_length))  # SPDU length
    udp_data += list(struct.pack('>I', block.prev_spduNum))  # SPDU number
    block.prev_spduNum += 1

    udp_data += [0x00, 0x02]  # Version (updated for CL crypto)
    udp_data += list(int(time.time()).to_bytes(4, 'big'))  # Timestamp
    
    # Add sender identity (IED name) - fixed length field of 16 bytes
    sender_bytes = sender_ied.encode('utf-8')[:16].ljust(16, b'\0')
    udp_data += list(sender_bytes)
    
    # Add serialized encrypted data
    serialized_enc_data = pickle.dumps(serialize_encrypted_data(encrypted_data))
    
    # Add length of encrypted data
    udp_data += list(struct.pack('>I', len(serialized_enc_data)))
    
    # Add encrypted data
    udp_data += list(serialized_enc_data)
    
    # Add serialized signature
    serialized_signature = pickle.dumps(serialize_signature(signature))
    
    # Add length of signature
    udp_data += list(struct.pack('>I', len(serialized_signature)))
    
    # Add signature
    udp_data += list(serialized_signature)
    
    # Add KGC public key for verification
    udp_data += list(struct.pack('>I', len(kgc_public_key)))
    udp_data += list(kgc_public_key)

    return udp_data

def send_packet(ifname, block, udp_data):
    sock = UdpSock()
    diagnose(sock.is_good(), "Opening datagram socket")

    groupSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    groupSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        iface_ip = getIPv4Add(ifname)
        groupSock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_pton(socket.AF_INET, iface_ip))
        groupSock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', 16))
    except Exception as e:
        print("Socket config error:", e)

    try:
        groupSock.sendto(bytearray(udp_data), (block.multicastIP, IEDUDPPORT))
        print(f"Sent {len(udp_data)} bytes to {block.multicastIP}:{IEDUDPPORT}")
    except Exception as e:
        print("Send error:", e)

def main(argv):
    sed_filename, ifname, ied_name = parse_arguments(argv)
    control_blocks = initialize_control_blocks(sed_filename, ied_name)

    s_value = 0
    while True:
        time.sleep(1)
        for block in control_blocks:
            block.s_value = s_value
            udp_data = build_udp_packet(block, s_value, ied_name)
            send_packet(ifname, block, udp_data)
            print("-" * 80)
        s_value += 1
        print("Resend...\n")

if __name__ == "__main__":
    main(sys.argv)

