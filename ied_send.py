import sys
import socket
import struct
import time
from ied_utils import *
from udpSock import *
from zz_diagnose import *
from parse_sed import *
import time
import math
import os
IEDUDPPORT = 102

import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
NONCE_SIZE = 12  # Nonce size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes
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

def set_timestamp(time_arr_out):
    # Get nanoseconds and seconds since epoch
    nanosec_since_epoch = int(time.time() * 1_000_000_000)
    sec_since_epoch = int(time.time())

    subsec_component = nanosec_since_epoch - (sec_since_epoch * 1_000_000_000)
    frac_sec = float(subsec_component)

    # Convert from [nanosecond] to [second]
    for _ in range(9):
        frac_sec /= 10

    # Convert to 3-byte (24-bit) fraction of second value (ref: ISO 9506-2)
    for _ in range(24):
        frac_sec *= 2

    frac_sec = round(frac_sec)
    subsec_component = int(frac_sec)

    # Set integer seconds in array's high order octets (0 to 3)
    for i in range(len(time_arr_out) // 2):
        time_arr_out[i] = (sec_since_epoch >> (24 - 8 * i)) & 0xff

    # Set fractional second in array's octets 4 to 6
    for i in range(len(time_arr_out) // 2, len(time_arr_out) - 1):
        time_arr_out[i] = (subsec_component >> (16 - 8 * (i - len(time_arr_out) // 2))) & 0xff

    # Debugging: Print values for inspection (if needed)
    # print(f"seconds since epoch: {sec_since_epoch}")
    # print(f"nanoseconds since epoch: {nanosec_since_epoch}")
    # print(f"round(frac_sec * 2^24): {frac_sec}")
    # print(f"frac_sec (integer): {subsec_component}")
    # for i, val in enumerate(time_arr_out):
    #     print(f"time_arr_out[{i}]: {val:02x}")

def set_gse_hardcoded_data(all_data_out, goose_data, loop_data):
    # Tag = 0x83 -> Data type: Boolean
    all_data_out.append(0x83)

    # Length = 0x01
    all_data_out.append(0x01)

    # Read the GOOSE data from file
    goose_counter = goose_data.goose_counter
    file_path = "GOOSEdata.txt"
    
    if not os.path.isfile(file_path):
        print("Failure to open.")
        return
    
    line = ""
    with open(file_path, 'r') as datafile:
        for _ in range(goose_counter):
            line = datafile.readline().strip()
    
    # Remove all whitespace characters from the line
    line = ''.join(line.split())
    
    # Ensure data provided is not empty
    if not line:
        raise ValueError("The line read from the file is empty.")
    
    # Determine the length of the cleaned line
    c = len(line)
    print("Number of characters: ",c)
    
    # Determine the value of s_value
    if loop_data:
        s_value = goose_data.s_value % c
    else:
        s_value = goose_data.s_value
    
    # Prevent overflow
    if s_value >= c:
        raise ValueError("s_value exceeds the length of the data.")

    # Debugging output
    print(f"GOOSEdata file values are: {', '.join(line)}")

    # Add the appropriate value to all_data_out based on s_value
    if line[s_value] == '0':
        all_data_out.append(0x00)
    else:
        all_data_out.append(0x01)

    # Debugging output to check size of all_data_out
    if len(all_data_out) != 3:
        raise ValueError("all_data_out does not have exactly 3 bytes.")

def convert_ieee(float_value):
    """Convert a float to IEEE 754 binary format."""
    return struct.pack('>f', float_value)

def set_sv_hardcoded_data(seq_of_data_value, sv_data, loop_data):
    sv_counter = sv_data.sv_counter
    file_path = "SVdata.txt"
    
    if not os.path.isfile(file_path):
        print("Failure to open.")
        return
    
    line = ""
    with open(file_path, 'r') as datafile:
        for _ in range(sv_counter):
            line = datafile.readline().strip()
    
    # Using whitespace to count the number of values
    values = line.split()
    v = len(values)
    
    # Ensure there are 4 voltage + 4 degree, 4 current + 4 degree values
    if v % 16 != 0:
        raise ValueError("Number of values is not a multiple of 16.")
    
    # Calculate s_value
    if loop_data:
        s_value = sv_data.s_value % (v // 16)
    else:
        s_value = sv_data.s_value
    
    s_value *= 16
    
    # Skip to the s_value position
    value_list = values[s_value:s_value + 16]
    
    # Debugging output
    print("SVdata file values are:", ', '.join(value_list))
    
    # Convert values to IEEE 754 format and append to seq_of_data_value
    for value in value_list:
        float_value = float(value)
        ieee_bytes = convert_ieee(float_value)
        seq_of_data_value.extend(ieee_bytes)
    
    # Ensure seq_of_data_value field has only the 64 bytes hardcoded from this function
    if len(seq_of_data_value) != 64:
        raise ValueError("seq_of_data_value does not have exactly 64 bytes.")

def convert_uint32_to_bytes(value):
    """Convert a 32-bit unsigned integer to bytes."""
    return struct.pack('>I', value)

def convert_ieee(float_value):
    """Convert a float to IEEE 754 binary format."""
    return struct.pack('>f', float_value)

def set_timestamp():
    """Generate a timestamp for demonstration purposes."""
    # This is a placeholder; implement this based on your actual needs
    return [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a]  # Example timestamp

def form_goose_pdu(goose_data, pdu_out):
    # Initialize variables for GOOSE PDU data
    goose_pdu_tag = 0x61
    goose_pdu_len = 0  # This will be updated later

    # *** GOOSE PDU -> gocbRef ***
    gocb_ref_tag = 0x80
    gocb_ref_value = goose_data.cbName.encode('utf-8')
    gocb_ref_len = len(gocb_ref_value)

    # *** GOOSE PDU -> timeAllowedToLive (in ms) ***
    time_allowed_to_live_tag = 0x81
    time_allowed_to_live_value = 0
    time_allowed_to_live_len = 0

    # *** GOOSE PDU -> datSet ***
    dat_set_tag = 0x82
    dat_set_value = goose_data.datSetName.encode('utf-8')
    dat_set_len = len(dat_set_value)

    # *** GOOSE PDU -> goID ***
    go_id_tag = 0x83
    go_id_value = goose_data.cbName.encode('utf-8')
    go_id_len = len(go_id_value)

    # *** GOOSE PDU -> t ***
    time_tag = 0x84
    time_len = 0x08
    time_value = set_timestamp()

    # *** GOOSE PDU -> stNum ***
    st_num_tag = 0x85
    st_num_value = 0
    st_num_len = 4

    # *** GOOSE PDU -> sqNum ***
    sq_num_tag = 0x86
    sq_num_value = 0
    sq_num_len = 4

    # *** GOOSE PDU -> test ***
    test_tag = 0x87
    test_value = 0x00
    test_len = 1

    # *** GOOSE PDU -> confRev ***
    conf_rev_tag = 0x88
    conf_rev_value = 0x01
    conf_rev_len = 1

    # *** GOOSE PDU -> ndsCom ***
    nds_com_tag = 0x89
    nds_com_value = 0x00
    nds_com_len = 1

    # *** GOOSE PDU -> numDatSetEntries ***
    num_dat_set_entries_tag = 0x8A
    num_dat_set_entries_value = 0x01
    num_dat_set_entries_len = 1

    # *** GOOSE PDU -> allData ***
    all_data_tag = 0xAB
    all_data_value = []
    set_gse_hardcoded_data(all_data_value, goose_data, True)
    # print("all data value")
    # print(all_data_value)
    all_data_len = len(all_data_value)

    # Determine stNum and sqNum based on state changes
    state_changed = goose_data.prev_allData_Value != all_data_value
    if state_changed:
        st_num_value = goose_data.prev_stNum_Value + 1
        sq_num_value = 0
        goose_data.prev_sqNum_Value = 0
    else:
        st_num_value = goose_data.prev_stNum_Value
        if goose_data.prev_sqNum_Value != 0xFFFFFFFF:
            sq_num_value = goose_data.prev_sqNum_Value + 1
        else:
            sq_num_value = 1
        goose_data.prev_sqNum_Value = sq_num_value

    # Determine timeAllowedToLive value
    if sq_num_value <= 5:
        time_allowed_to_live_value = 20
        time_allowed_to_live_len = 1
    elif sq_num_value == 6:
        time_allowed_to_live_value = 32
        time_allowed_to_live_len = 1
    elif sq_num_value == 7:
        time_allowed_to_live_value = 64
        time_allowed_to_live_len = 1
    elif sq_num_value == 8:
        time_allowed_to_live_value = 128
        time_allowed_to_live_len = 1
    elif sq_num_value == 9:
        time_allowed_to_live_value = 256
        time_allowed_to_live_len = 2
    elif sq_num_value == 10:
        time_allowed_to_live_value = 512
        time_allowed_to_live_len = 2
    elif sq_num_value == 11:
        time_allowed_to_live_value = 1024
        time_allowed_to_live_len = 2
    elif sq_num_value == 12:
        time_allowed_to_live_value = 2048
        time_allowed_to_live_len = 2
    else:
        time_allowed_to_live_value = 4000
        time_allowed_to_live_len = 2


    # Fill pdu_out with data
    pdu_out.append(goose_pdu_tag)
    pdu_out.append(goose_pdu_len)  # Placeholder for PDU length

    # Add components to PDU
    pdu_out.extend([gocb_ref_tag, gocb_ref_len])
    pdu_out.extend(gocb_ref_value)

    pdu_out.extend([time_allowed_to_live_tag, time_allowed_to_live_len])
    # print("length of time allowed to live ",len(list(convert_uint32_to_bytes(time_allowed_to_live_value))))
    pdu_out.extend(convert_uint32_to_bytes(time_allowed_to_live_value))

    pdu_out.extend([dat_set_tag, dat_set_len])
    pdu_out.extend(dat_set_value)

    pdu_out.extend([go_id_tag, go_id_len])
    pdu_out.extend(go_id_value)

    pdu_out.extend([time_tag, time_len])
    pdu_out.extend(time_value)

    pdu_out.extend([st_num_tag, st_num_len])
    # print("sdfghj",len(list(convert_uint32_to_bytes(time_allowed_to_live_value))))
    pdu_out.extend(convert_uint32_to_bytes(st_num_value))

    pdu_out.extend([sq_num_tag, sq_num_len])
    pdu_out.extend(convert_uint32_to_bytes(sq_num_value))

    pdu_out.extend([test_tag, test_len])
    pdu_out.append(test_value)

    pdu_out.extend([conf_rev_tag, conf_rev_len])
    pdu_out.append(conf_rev_value)

    pdu_out.extend([nds_com_tag, nds_com_len])
    pdu_out.append(nds_com_value)

    pdu_out.extend([num_dat_set_entries_tag, num_dat_set_entries_len])
    pdu_out.append(num_dat_set_entries_value)

    pdu_out.extend([all_data_tag, all_data_len])
    pdu_out.extend(all_data_value)

    # Update PDU length
    pdu_out[1] = len(pdu_out)

    # Update historical allData
    goose_data.prev_allData_Value = all_data_value

def form_sv_pdu(sv_data, pdu_out):
    # Initialize variables for SV PDU data
    sv_pdu_tag = 0x60
    sv_pdu_len = 0  # Includes SV PDU Tag & Len and every component's length

    no_asdu_tag = 0x80
    no_asdu_len = 0x01
    no_asdu_value = 0x01  # Fixed as 1 for IEC 61850-9-2 LE implementation

    seq_of_asdu_tag = 0xA2
    seq_of_asdu_len = 0

    # SV ASDU
    asdu_tag = 0x30
    asdu_len = 0

    # SV ASDU -> MsvID
    sv_id_tag = 0x80
    sv_id_len = len(sv_data.cbName)
    sv_id_value = sv_data.cbName.encode('utf-8')

    # SV ASDU -> smpCnt
    smp_cnt_tag = 0x82
    smp_cnt_len = 0x02
    smp_cnt_value = 0

    # SV ASDU -> confRev
    conf_rev_tag = 0x83
    conf_rev_len = 0x04
    conf_rev_value = 1

    # SV ASDU -> smpSynch
    smp_synch_tag = 0x85
    smp_synch_len = 0x01
    smp_synch_value = 0x02  # Fixed as 2 in this implementation

    # SV ASDU -> Sample
    seq_of_data_tag = 0x87
    seq_of_data_len = 0
    seq_of_data_value = []

    # HARDCODED Sample Data in this implementation
    set_sv_hardcoded_data(seq_of_data_value, sv_data, True)

    seq_of_data_len = len(seq_of_data_value)

    # SV ASDU -> t
    time_tag = 0x89
    time_len = 0x08
    time_value = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a])

    # Set smpCnt Value (assume 50Hz)
    if sv_data.prev_smpCnt_Value != 3999:
        smp_cnt_value = sv_data.prev_smpCnt_Value
        sv_data.prev_smpCnt_Value += 1
    else:
        smp_cnt_value = 0
        sv_data.prev_smpCnt_Value = 0

    # Set ASDU Length
    asdu_content = bytearray()
    asdu_content.append(asdu_tag)
    asdu_content.append(asdu_len)

    asdu_content.append(sv_id_tag)
    asdu_content.append(sv_id_len)
    asdu_content.extend(sv_id_value)

    asdu_content.append(smp_cnt_tag)
    asdu_content.append(smp_cnt_len)
    smp_cnt_val_vec = smp_cnt_value.to_bytes(2, byteorder='big')
    if len(smp_cnt_val_vec) == 1:
        asdu_content.append(0x00)  # Pad with a higher-order byte 0x00
    asdu_content.extend(smp_cnt_val_vec)

    asdu_content.append(conf_rev_tag)
    asdu_content.append(conf_rev_len)
    asdu_content.extend(conf_rev_value.to_bytes(4, byteorder='big'))

    asdu_content.append(smp_synch_tag)
    asdu_content.append(smp_synch_len)
    asdu_content.append(smp_synch_value)

    asdu_content.append(seq_of_data_tag)
    asdu_content.append(seq_of_data_len)
    asdu_content.extend(seq_of_data_value)

    asdu_content.append(time_tag)
    asdu_content.append(time_len)
    asdu_content.extend(time_value)

    # Set ASDU Length
    asdu_len = len(asdu_content)
    asdu_content[1] = asdu_len

    # Form SV PDU
    seq_of_asdu_len = len(asdu_content) + 2
    sv_pdu_len = seq_of_asdu_len + 5

    pdu_out.append(sv_pdu_tag)
    pdu_out.append(sv_pdu_len)

    pdu_out.append(no_asdu_tag)
    pdu_out.append(no_asdu_len)
    pdu_out.append(no_asdu_value)
    pdu_out.append(seq_of_asdu_tag)
    pdu_out.append(seq_of_asdu_len)

    pdu_out.extend(asdu_content)

    # Update historical allData before exiting function
    sv_data.prev_seqOfData_Value = seq_of_data_value


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

    # Keep looping to send multicast messages

    # print(ownControlBlocks)    
    s = set()
    s_value = 0
    while True:
        time.sleep(1)  # in seconds

        # Form network packet for each Control Block
        for i in range(len(ownControlBlocks)):
            # For forming Payload in Application Profile
            payload = []
            
            # PDU will be part of Payload
            pdu = []

            if ownControlBlocks[i].cbType == f"{namespace}GSE":
                print("cbName", ownControlBlocks[i].cbName)
                ownControlBlocks[i].s_value = s_value
                form_goose_pdu(ownControlBlocks[i], pdu)
                # Payload Type 0x81: non-tunneled GOOSE APDU
                payload.append(0x81)

            elif ownControlBlocks[i].cbType == f"{namespace}SMV":
                # continue
                print("cbName", ownControlBlocks[i].cbName)
                ownControlBlocks[i].s_value = s_value
                form_sv_pdu(ownControlBlocks[i], pdu)

                print("pdu: ",bytearray(pdu))
                # Payload Type 0x82: non-tunneled SV APDU
                payload.append(0x82)

            # Continue forming Payload
            payload.append(0x00)  # Simulation 0x00: Boolean False = payload not sent for test

            # APP ID

            raw_converted_appid = int(ownControlBlocks[i].appID, 16)
            payload.append((raw_converted_appid >> 8) & 0xFF)
            payload.append(raw_converted_appid & 0xFF)

            # APDU Length
            apdu_len = len(pdu) + 2  # Length of SV or GOOSE PDU plus the APDU Length field itself
            payload.append((apdu_len >> 8) & 0xFF)
            payload.append(apdu_len & 0xFF)

            # PDU
            # print("PDU: ",pdu)
            payload.extend(pdu)

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

            # Security Information (not used in this implementation, hence set to 0's)
            for _ in range(12):
                udp_data.append(0x00)

            # Form the Session User Information: prepend Payload Length to & append Signature to the Payload
            payload_len = len(payload) + 4  # Length of Payload plus Payload Length field itself
            udp_data.append((payload_len >> 24) & 0xFF)
            udp_data.append((payload_len >> 16) & 0xFF)
            udp_data.append((payload_len >> 8) & 0xFF)
            udp_data.append(payload_len & 0xFF)
            
            
            if(False):
                key = os.urandom(AES_KEY_SIZE)
                encrypted_payload = encrypt_aes_gcm(bytes(payload), key)
                if(ownControlBlocks[i].cbType == f"{namespace}GSE"):
                    print("Encrypted GOOSE PDU:", encrypted_payload)
                else:
                    print("Encrypted SV PDU:", encrypted_payload)
                udp_data.extend(encrypted_payload)
            else:
                udp_data.extend(payload)

            # Signature Tag = 0x85                
            udp_data.append(0x85)

            # Length of HMAC considered as zero in this implementation
            udp_data.append(0x00)  # Application Profile = UDP Data completely formed here
            # st = ''.join(map(str,udp_data))
            # if st in s:
            #     print("HAWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
            # s.add(st)
            # Send via UDP multicast (ref: udpSock.hpp)
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
