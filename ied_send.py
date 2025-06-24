# send file
import sys
import socket
import struct
import time
from ied_utils import *
from udpSock import *
from zz_diagnose import *
from parse_sed import *
import time
import os

from CLC import get_public_key, get_timestamp, CertificatelessCrypto
from compression_encryption import compress_data, encrypt_aes_gcm, decrypt_aes_gcm, key, generate_hmac_cryptography

from KGC import KeyGenerationCenter


HEADER_LENGTH = 18  # Length of the PDU header (example)
NONCE_SIZE = 12  # Nonce size for AES-GCM in bytes
TAG_SIZE = 16  # Tag size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes

IEDUDPPORT = 102

from form_pdu import form_goose_pdu, form_sv_pdu

total_encrypt_time = 0
total_packets = 0

def main(argv):
    if len(argv) != 4:
        if argv[0]:
            print(f"Usage: {argv[0]} <SED Filename> <Interface Name to be used on IED> <IED Name>")
        else:
            # For OS where argv[0] can end up as an empty string instead of the program's name.
            print("Usage: <program name> <SED Filename> <Interface Name to be used on IED> <IED Name>")
        return 1

    # Specify SED Filename
    sed_filename = argv[1]
    

    # Specify Network Interface Name to be used on IED for inter-substation communication
    ifname = argv[2]
    
    # Save IPv4 address of specified Network Interface into ifr structure: ifr
    ifr = getIPv4Add(ifname)
    ifr = socket.inet_pton(socket.AF_INET,ifr)

    # Specify IED name
    ied_name = argv[3]

    # Specify filename to parse
    vector_of_ctrl_blks = parse_sed(sed_filename)

    # Find relevant Control Blocks pertaining to IED
    ownControlBlocks = []
    goose_counter = 0
    sv_counter = 0

    namespace = '{http://www.iec.ch/61850/2003/SCL}'

    for it in vector_of_ctrl_blks:
        if it.hostIED == ied_name:
            if it.cbType == f'{namespace}GSE':
                goose_counter += 1
                tmp_goose_data = GooseSvData()
                
                tmp_goose_data.cbName = it.cbName
                tmp_goose_data.cbType = it.cbType
                tmp_goose_data.appID = it.appID
                tmp_goose_data.multicastIP = it.multicastIP
                tmp_goose_data.datSetName = it.datSetName
                tmp_goose_data.goose_counter = goose_counter

                ownControlBlocks.append(tmp_goose_data)
            
            elif it.cbType == f"{namespace}SMV":
                sv_counter += 1
                tmp_sv_data = GooseSvData()
                
                tmp_sv_data.cbName = it.cbName
                tmp_sv_data.cbType = it.cbType
                tmp_sv_data.appID = it.appID
                tmp_sv_data.multicastIP = it.multicastIP
                tmp_sv_data.sv_counter = sv_counter

                ownControlBlocks.append(tmp_sv_data)
    demo_data = encrypt_aes_gcm(bytes([123]))
    decrypt_aes_gcm(demo_data)
    # Keep looping to send multicast messages
    s = set()
    s_value = 0
    while True:
        time.sleep(1)  # in seconds
        # Initialize crypto
        kgc = KeyGenerationCenter()  # Simulated shared KGC
        
        receiver_identity = ied_name 
        receiver_pubkey_pem = get_public_key('./keys/public_key.pem')
        
        sender_crypto = CertificatelessCrypto(key_dir='./sender_keys', rotation_interval=30)
        sender_crypto.initialize_with_partial_key(ied_name, kgc)


        # Form network packet for each Control Block
        for i in range(len(ownControlBlocks)):
            # For forming Payload in Application Profile
            payload = []
            
            # PDU will be part of Payload
            pdu_1 = []

            if ownControlBlocks[i].cbType == f"{namespace}GSE":
                print("cbName", ownControlBlocks[i].cbName)
                ownControlBlocks[i].s_value = s_value
                form_goose_pdu(ownControlBlocks[i], pdu_1)
                # Payload Type 0x81: non-tunneled GOOSE APDU
                payload.append(0x81)

            elif ownControlBlocks[i].cbType == f"{namespace}SMV":
                # continue
                print("cbName", ownControlBlocks[i].cbName)
                ownControlBlocks[i].s_value = s_value
                form_sv_pdu(ownControlBlocks[i], pdu_1)
                
                # Payload Type 0x82: non-tunneled SV APDU
                payload.append(0x82)

            # Continue forming Payload
            payload.append(0x00)  # Simulation 0x00: Boolean False = payload not sent for test

            # APP ID
            raw_converted_appid = int(ownControlBlocks[i].appID, 16)
            payload.append((raw_converted_appid >> 8) & 0xFF)
            payload.append(raw_converted_appid & 0xFF)

            # APDU Length
            apdu_len = len(pdu_1) + 2  # Length of SV or GOOSE PDU plus the APDU Length field itself
            payload.append((apdu_len >> 8) & 0xFF)
            payload.append(apdu_len & 0xFF)

            # PDU
            payload.extend(pdu_1)
            
            # Based on RFC-1240 protocol (OSI connectionless transport services on top of UDP)
            udp_data = []
            udp_data.append(0x01)  # Length Identifier (LI)
            udp_data.append(0x40)  # Transport Identifier (TI)

            # Based on IEC 61850-90-5 session protocol specification
            if ownControlBlocks[i].cbType == f"{namespace}GSE":
                udp_data.append(0xA1)  # 0xA1: non-tunneled GOOSE APDU
            elif ownControlBlocks[i].cbType == f"{namespace}SMV":
                udp_data.append(0xA2)  # 0xA2: non-tunneled SV APDU

            udp_data.append(0x18)  # Length Identifier (LI)

            # Common session header
            udp_data.append(0x80)  # Parameter Identifier (PI) of 0x80 as per IEC 61850-90-5
            udp_data.append(0x16)  # Length Identifier (LI)

            # SPDU Length (fixed size 4-byte word with maximum value of 65,517)
            spdu_length = (4 + 2) + 12 + 4 + len(payload) + 2
            udp_data.append((spdu_length >> 24) & 0xFF)
            udp_data.append((spdu_length >> 16) & 0xFF)
            udp_data.append((spdu_length >> 8) & 0xFF)
            udp_data.append(spdu_length & 0xFF)

            # SPDU Number (fixed size 4-byte unsigned integer word)
            current_SPDUNum = ownControlBlocks[i].prev_spduNum
            ownControlBlocks[i].prev_spduNum += 1
            udp_data.append((current_SPDUNum >> 24) & 0xFF)
            udp_data.append((current_SPDUNum >> 16) & 0xFF)
            udp_data.append((current_SPDUNum >> 8) & 0xFF)
            udp_data.append(current_SPDUNum & 0xFF)

            # Version Number (fixed 2-byte unsigned integer, assigned to 1 in this implementation)

            udp_data.append(0x00)
            udp_data.append(0x01)
            
            timestamp = int(time.time()).to_bytes(4, 'big')  # Current timestamp
            udp_data.extend(timestamp)
            key_rotation_minutes = (60).to_bytes(2, 'big')  # 1-hour key rotation
            udp_data.extend(key_rotation_minutes)
            encryption_algorithm = b'\x01'  # Example: AES-GCM
            message_auth_algorithm = b'\x02'  # Example: HMAC-SHA256-128
            udp_data.extend(encryption_algorithm)
            udp_data.extend(message_auth_algorithm)
            key_id = os.urandom(4)  # Use a random 4-byte key ID
            udp_data.extend(key_id)

            # Form the Session User Information: prepend Payload Length to & append Signature to the Payload
            payload_len = len(payload) + 4  # Length of Payload plus Payload Length field itself
            udp_data.append((payload_len >> 24) & 0xFF)
            udp_data.append((payload_len >> 16) & 0xFF)
            udp_data.append((payload_len >> 8) & 0xFF)
            udp_data.append(payload_len & 0xFF)
            
            print(len(udp_data))
            print("Payload length before encryption/compression",len(payload))

            start_time = time.time()*1000
            payload = (compress_data(bytes(payload)))
            # payload = (encrypt_aes_gcm(bytes(payload)))

            payload = sender_crypto.encrypt_bytes(payload, receiver_pubkey_pem)

            udp_data.extend(payload)

            # Signature Tag = 0x85                
            udp_data.append(0x85)
            
            # Length of HMAC 
            udp_data.append(0x20)

            t1  = time.time()
            udp_data.extend(generate_hmac_cryptography(key, udp_data))
            t2  = time.time()
            print("Mac generation time : ", t2-t1)

            sock = UdpSock()
            diagnose(sock.is_good(), "Opening datagram socket for send")

            # Set multicast protocol network parameters
            groupSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            groupSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                groupSock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, ifr)
                print("Setting local Interface: ",ifname)
            except Exception as e:
                print("Error setting local interface:", e)

            try:
                TTL = 16
                groupSock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', TTL))
                current_ttl = struct.unpack('b', groupSock.getsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1))[0]
                print("TTL set to:", current_ttl)
            except Exception as e:
                print("Error setting multicast TTL:", e)

            try:
                groupSock.sendto(bytearray(udp_data), (ownControlBlocks[i].multicastIP, IEDUDPPORT))
                print(len(udp_data),"bytes Data sent to:", ownControlBlocks[i].multicastIP, "on port", IEDUDPPORT)
            except Exception as e:
                print("Error sending data:", e)

            print(udp_data)
            print('-------------------------------------------------------------------------------')
        s_value += 1
        print("Resend")
        print()
    return 0
if __name__ == "__main__":
    main(sys.argv)