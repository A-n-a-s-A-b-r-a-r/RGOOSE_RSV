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

HEADER_LENGTH = 18  # Length of the PDU header (example)
NONCE_SIZE = 12  # Nonce size for AES-GCM in bytes
TAG_SIZE = 16  # Tag size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes


IEDUDPPORT = 102
from form_pdu import form_goose_pdu, form_sv_pdu
from compression_encryption import compress_data, decompress_data, encrypt_aes_gcm, decrypt_aes_gcm;

total_encrypt_time = 0
total_packets = 0
encrypt_compress = True
# def set_timestamp(time_arr_out):
#     # Get nanoseconds and seconds since epoch
#     nanosec_since_epoch = int(time.time() * 1_000_000_000)
#     sec_since_epoch = int(time.time())

#     subsec_component = nanosec_since_epoch - (sec_since_epoch * 1_000_000_000)
#     frac_sec = float(subsec_component)

#     # Convert from [nanosecond] to [second]
#     for _ in range(9):
#         frac_sec /= 10

#     # Convert to 3-byte (24-bit) fraction of second value (ref: ISO 9506-2)
#     for _ in range(24):
#         frac_sec *= 2

#     frac_sec = round(frac_sec)
#     subsec_component = int(frac_sec)

#     # Set integer seconds in array's high order octets (0 to 3)
#     for i in range(len(time_arr_out) // 2):
#         time_arr_out[i] = (sec_since_epoch >> (24 - 8 * i)) & 0xff

#     # Set fractional second in array's octets 4 to 6
#     for i in range(len(time_arr_out) // 2, len(time_arr_out) - 1):
#         time_arr_out[i] = (subsec_component >> (16 - 8 * (i - len(time_arr_out) // 2))) & 0xff

#     # Debugging: Print values for inspection (if needed)
#     # print(f"seconds since epoch: {sec_since_epoch}")
#     # print(f"nanoseconds since epoch: {nanosec_since_epoch}")
#     # print(f"round(frac_sec * 2^24): {frac_sec}")
#     # print(f"frac_sec (integer): {subsec_component}")
#     # for i, val in enumerate(time_arr_out):
#     #     print(f"time_arr_out[{i}]: {val:02x}")


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

        # Form network packet for each Control Block
        for i in range(len(ownControlBlocks)):
            # For forming Payload in Application Profile
            payload = []
            
            # PDU will be part of Payload
            pdu_1 = []
            pdu_2 = []

            if ownControlBlocks[i].cbType == f"{namespace}GSE":
                print("cbName", ownControlBlocks[i].cbName)
                ownControlBlocks[i].s_value = s_value
                form_goose_pdu(ownControlBlocks[i], pdu_1)
                
                
                s_value += 1
                ownControlBlocks[i].s_value = s_value
                form_goose_pdu(ownControlBlocks[i], pdu_2)



                # Payload Type 0x81: non-tunneled GOOSE APDU
                payload.append(0x81)



            elif ownControlBlocks[i].cbType == f"{namespace}SMV":
                # continue
                print("cbName", ownControlBlocks[i].cbName)
                ownControlBlocks[i].s_value = s_value
                form_sv_pdu(ownControlBlocks[i], pdu_1)
                
                
                s_value += 1
                ownControlBlocks[i].s_value = s_value
                form_sv_pdu(ownControlBlocks[i], pdu_2)



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
            # print("PDU: ",pdu_1)
            payload.extend(pdu_1)
            




            payload.append(0xff)
            payload.append(0xff)


            if ownControlBlocks[i].cbType == f"{namespace}GSE":
                payload.append(0x81)
            if ownControlBlocks[i].cbType == f"{namespace}SMV":
                payload.append(0x82)
            
            # Continue forming Payload
            payload.append(0x00)  # Simulation 0x00: Boolean False = payload not sent for test

            # APP ID
            raw_converted_appid = int(ownControlBlocks[i].appID, 16)
            payload.append((raw_converted_appid >> 8) & 0xFF)
            payload.append(raw_converted_appid & 0xFF)

            # APDU Length
            apdu_len = len(pdu_2) + 2  # Length of SV or GOOSE PDU plus the APDU Length field itself
            payload.append((apdu_len >> 8) & 0xFF)
            payload.append(apdu_len & 0xFF)
            
            # PDU
            payload.extend(pdu_2)



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
            
            # # Security Information (not used in this implementation, hence set to 0's)
            # for _ in range(12):
            #     udp_data.append(0x00)
            
            # Security information added for testing purpose using AES GCM
            # Comment this part when not using encryption and instead just add 12 bytes of padding
            if encrypt_compress :
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
            else :
                for _ in range(12):
                   udp_data.append(0x00)
                

            # Form the Session User Information: prepend Payload Length to & append Signature to the Payload
            payload_len = len(payload) + 4  # Length of Payload plus Payload Length field itself
            udp_data.append((payload_len >> 24) & 0xFF)
            udp_data.append((payload_len >> 16) & 0xFF)
            udp_data.append((payload_len >> 8) & 0xFF)
            udp_data.append(payload_len & 0xFF)
            
            print(len(udp_data))
            print("Payload length before encryption/compression",len(payload))

            start_time = time.time()*1000
            if  encrypt_compress:
                # payload = list(compress_data(bytes(payload)))
                payload = list(encrypt_aes_gcm(bytes(payload)))
                end_time = time.time()*1000
                global total_encrypt_time, total_packets
                total_encrypt_time += (end_time - start_time)
                total_packets +=1
                print("total packets: ",total_packets)
                print("Average Time taken by encryption/compression: ", round(total_encrypt_time/total_packets, 3), "ms")
            udp_data.extend(payload)

            # Signature Tag = 0x85                
            udp_data.append(0x85)

            # Length of HMAC considered as zero in this implementation
            udp_data.append(0x00)  # Application Profile = UDP Data completely formed here

            
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
                # udp_data = bytearray(udp_data)
                # Make sure udp_data, ownControlBlocks, and IEDUDPPORT are properly defined
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