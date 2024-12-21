# A collection of data structure and functions for IED operations/debugging
import socket
# import fcntl
from typing import List
# GOOSE/SV Data to be tracked per sending/receiving cycle
class GooseSvData:
    def __init__(self):
        self.cbName = ""
        self.cbType = ""
        self.appID = ""
        self.multicastIP = ""
        self.prev_spduNum = 0
        self.s_value = 0

        # Specific to GOOSE
        self.datSetName = ""
        self.goose_counter = 0
        self.prev_stNum_Value = 0
        self.prev_sqNum_Value = 0
        self.prev_numDatSetEntries = 0
        self.prev_allData_Value = []

        # Specific to SV (Based on IEC 61850-9-2 Light Edition (LE) implementation)
        self.prev_smpCnt_Value = 0
        self.prev_seqOfData_Value = []
        self.sv_counter = 0

    def __str__(self):
        return (
            f"GooseSvData(cbName={self.cbName}, cbType={self.cbType}, appID={self.appID}, \n"
            f"multicastIP={self.multicastIP}, prev_spduNum={self.prev_spduNum}, s_value={self.s_value}, \n"
            f"datSetName={self.datSetName}, goose_counter={self.goose_counter}, \n"
            f"prev_stNum_Value={self.prev_stNum_Value}, prev_sqNum_Value={self.prev_sqNum_Value}, \n"
            f"prev_numDatSetEntries={self.prev_numDatSetEntries}, prev_allData_Value={self.prev_allData_Value}, \n"
            f"prev_smpCnt_Value={self.prev_smpCnt_Value}, prev_seqOfData_Value={self.prev_seqOfData_Value}, \n"
            f"sv_counter={self.sv_counter}) \n"
            "\n"
        )
    def __repr__(self):
        return (
            f"GooseSvData(cbName={self.cbName}, cbType={self.cbType}, appID={self.appID}, \n"
            f"multicastIP={self.multicastIP}, prev_spduNum={self.prev_spduNum}, s_value={self.s_value}, \n"
            f"datSetName={self.datSetName}, goose_counter={self.goose_counter}, \n"
            f"prev_stNum_Value={self.prev_stNum_Value}, prev_sqNum_Value={self.prev_sqNum_Value}, \n"
            f"prev_numDatSetEntries={self.prev_numDatSetEntries}, prev_allData_Value={self.prev_allData_Value}, \n"
            f"prev_smpCnt_Value={self.prev_smpCnt_Value}, prev_seqOfData_Value={self.prev_seqOfData_Value}, \n"
            f"sv_counter={self.sv_counter}) \n"
            "\n"
        )
        

class IEEEfloat:
    def __init__(self):
        self.raw = self.Raw()

    class Raw:
        def __init__(self):
            self.mantissa = 0
            self.exponent = 0
            self.sign = 0


import psutil
import socket
def getIPv4Add(ifname):
    def list_network_interfaces():
        net_if_addrs = psutil.net_if_addrs()
        return list(net_if_addrs.keys())

    print("Available interfaces:", list_network_interfaces())
    try:
        net_if_addrs = psutil.net_if_addrs()
        for addr in net_if_addrs[ifname]:
            if addr.family == socket.AF_INET:
                return addr.address
    except KeyError as e:
        print(f"Error: Interface {ifname} not found")
        return None



# Function to iterate over the contents of a list and print all elements using indexing
def display_vector(vec):
    if len(vec) > 0:
        print("[ ", end="")
        for i in range(len(vec) - 1):
            print(f"{vec[i]}, ", end="")
        print(f"{vec[-1]} ]")
    else:
        print("Vector is empty!")


# ControlBlock class as a placeholder
class ControlBlock:
    def __init__(self, hostIED, cbType, multicastIP, appID, vlanID, cbName, datSetName, datSetVector, subscribingIEDs):
        self.hostIED = hostIED
        self.cbType = cbType
        self.multicastIP = multicastIP
        self.appID = appID
        self.cbName = cbName
        self.datSetName = datSetName
        self.subscribingIEDs = subscribingIEDs
        
        self.datSetVector = datSetVector
        self.vlanID = vlanID


# Function to print values of variables in a given Control Block
def printControlBlock(ctrl_blk):
    print(f"\tHost IED \t\t\t= {ctrl_blk.hostIED}")
    print(f"\tControl Block type \t\t= {ctrl_blk.cbType}")
    print(f"\tMulticast IP Address \t\t= {ctrl_blk.multicastIP}")
    print(f"\tAPP ID \t\t\t\t= {ctrl_blk.appID}")
    print(f"\tVLAN ID \t\t\t= {ctrl_blk.vlanID}")
    print(f"\tFully qualified cbName \t\t= {ctrl_blk.cbName}")
    print(f"\tFully qualified datSetName \t= {ctrl_blk.datSetName}")
    print(f"\tInformation Model \t\t= ", end="")
    display_vector(ctrl_blk.datSetVector)
    print("\n\tSubscribing IED(s) \t\t= ", end="")
    display_vector(ctrl_blk.subscribingIEDs)
    print()

def printCtrlBlkVect(vector_of_ctrl_blks: List['ControlBlock']):
    print(f"Total of {len(vector_of_ctrl_blks)} Control Block(s) in the following vector:\n    {{")

    for i, ctrl_blk in enumerate(vector_of_ctrl_blks):
        printControlBlock(ctrl_blk)
        if i != len(vector_of_ctrl_blks) - 1:
            print("\n    ,")

    print("\n    }\n\n")


# Returns the number of bytes to hold a given UINT32 number
def getUINT32Length(num: int) -> int:
    if num < 0x10000:
        if num < 0x100:
            return 0x01
        else:
            return 0x02
    else:
        if num < 0x1000000:
            return 0x03
        else:
            return 0x04


# Converts a given UINT32 number into a list of up to 4 bytes
def convertUINT32IntoBytes(num: int) -> List[int]:
    vecOut = []
    byte_count = getUINT32Length(num)

    mask0 = 0xFF000000
    mask1 = 0x00FF0000
    mask2 = 0x0000FF00
    mask3 = 0x000000FF

    if byte_count == 4:
        vecOut.append((mask0 & num) >> 24)
    if byte_count >= 3:
        vecOut.append((mask1 & num) >> 16)
    if byte_count >= 2:
        vecOut.append((mask2 & num) >> 8)
    if byte_count >= 1:
        vecOut.append(mask3 & num)

    assert 1 <= len(vecOut) <= 4
    return vecOut

def getHexFromBinary(binaryString: str) -> List[int]:
    # Pad binaryString to ensure it is a multiple of 8 bits
    binaryString = binaryString.zfill((len(binaryString) + 7) // 8 * 8)
    
    result = 0
    for count in range(len(binaryString)):
        result *= 2
        result += 1 if binaryString[count] == '1' else 0

    seqOfData_Value = []
    hex_value = hex(result)[2:].zfill((len(binaryString) // 8) * 2)  # Remove '0x' and pad with zeros
    for i in range(0, len(hex_value), 2):
        seqOfData_Value.append(int(hex_value[i:i+2], 16))

    return seqOfData_Value



def convertBinary(n: int, i: int) -> List[str]:
    buffer = []
    for k in range(i - 1, -1, -1):
        buffer.append('1' if (n >> k) & 1 else '0')

    return buffer


def convertToInt(dataBytes: List[int], low: int, high: int) -> int:
    f = 0
    for i in range(high, low - 1, -1):
        f += dataBytes[i] * (2 ** (high - i))
    return f


def convertIEEE(var: 'IEEEfloat') -> List[int]:
    buffer = []

    # Add sign bit
    buffer.append('1' if var.raw.sign else '0')

    # Convert float to binary
    buffer.extend(convertBinary(var.raw.exponent, 8))
    buffer.extend(convertBinary(var.raw.mantissa, 23))

    seqOfData_Value = []
    for i in range(0, len(buffer), 8):
        binaryString = ''.join(buffer[i:i+8])
        seqOfData_Value.extend(getHexFromBinary(binaryString))

    return seqOfData_Value
