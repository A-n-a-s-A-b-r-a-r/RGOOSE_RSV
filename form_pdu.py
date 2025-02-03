import os,struct

import time
from datetime import datetime
def set_timestamp():
    """Generate a timestamp for demonstration purposes."""
    utc_timestamp = time.time()  # Get current UTC timestamp as an integer
    print("Timestamp: ",datetime.fromtimestamp(utc_timestamp))
    return struct.pack('>d', utc_timestamp)  # Pack it into 8 bytes (big-endian)

''' duplicate: not in use currently'''
def convert_uint32_to_bytes(value):
    return struct.pack('>I', value)  # Convert a 32-bit unsigned integer to bytes.


def convert_ieee(float_value):
    """Convert a float to IEEE 754 binary format."""
    return struct.pack('>f', float_value)


def set_gse_hardcoded_data(all_data_out, goose_data, loop_data):
    # Tag = 0x83 -> Data type: Boolean
    all_data_out.append(0x83)

    # Length = 0x01
    all_data_out.append(0x01)



    # Read the GOOSE data from file
    goose_counter = goose_data.goose_counter
    file_path = "GOOSEdata.txt"
    
    with  open(file_path, 'r') as datafile:
        ans = len(datafile.readlines())



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
    
    print("Goose_COUNTER : ",goose_data.s_value, " ", ans)


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

    goose_data.goose_counter %= ans
    goose_data.goose_counter += 1

    # Debugging output to check size of all_data_out
    if len(all_data_out) != 3:
        raise ValueError("all_data_out does not have exactly 3 bytes.")

def set_sv_hardcoded_data(seq_of_data_value, sv_data, loop_data):
    sv_counter = sv_data.sv_counter
    file_path = "SVdata.txt"
    
    if not os.path.isfile(file_path):
        print("Failure to open.")
        return
    
    line = ""
    with open(file_path, 'r') as datafile:
        line = datafile.read().strip()
    
    # Using whitespace to count the number of values
    values = line.split()
    v = len(values)

    # print(values)
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
    

    if sv_counter >= s_value:
        sv_data.sv_counter = 1
    else:
        sv_data.sv_counter += 1

    
    # Ensure seq_of_data_value field has only the 64 bytes hardcoded from this function
    if len(seq_of_data_value) != 64:
        raise ValueError("seq_of_data_value does not have exactly 64 bytes.")

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
    from ied_utils import convertUINT32IntoBytes
    # pdu_out.extend(convert_uint32_to_bytes(time_allowed_to_live_value))
    pdu_out.extend(convertUINT32IntoBytes(time_allowed_to_live_value))

    pdu_out.extend([dat_set_tag, dat_set_len])
    pdu_out.extend(dat_set_value)

    pdu_out.extend([go_id_tag, go_id_len])
    pdu_out.extend(go_id_value)

    pdu_out.extend([time_tag, time_len])
    pdu_out.extend(time_value)     # before
    # pdu_out.extend(set_timestamp()) # after

    pdu_out.extend([st_num_tag, st_num_len])
    # print("sdfghj",len(list(convert_uint32_to_bytes(time_allowed_to_live_value))))
    
    # pdu_out.extend(convert_uint32_to_bytes(st_num_value))
    pdu_out.extend(convertUINT32IntoBytes(st_num_value))

    pdu_out.extend([sq_num_tag, sq_num_len])
    
    
    pdu_out.extend(convertUINT32IntoBytes(sq_num_value))
    # pdu_out.extend(convert_uint32_to_bytes(sq_num_value))

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

    # SV ASDU -> t
    time_tag = 0x89
    time_len = 0x08
    time_value = set_timestamp()

    # HARDCODED Sample Data in this implementation
    set_sv_hardcoded_data(seq_of_data_value, sv_data, True)

    seq_of_data_len = len(seq_of_data_value)


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
    asdu_content.extend(time_value) #before
    # asdu_content.extend(set_timestamp()) #after

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

