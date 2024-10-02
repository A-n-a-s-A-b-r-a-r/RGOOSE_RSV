import socket
import struct
import sys
import ipaddress
from ied_utils  import *
from parse_sed import *
from zz_diagnose import *
from udpSock import *
import struct
import sys

IEDUDPPORT = 102
MAXBUFLEN = 1024
namespace = '{http://www.iec.ch/61850/2003/SCL}'

def valid_GSE_SMV(buf, numbytes, cbOut):
    if numbytes > MAXBUFLEN or numbytes < 40:
        print("[!] Error: Buffer length out of range", file=sys.stderr)
        return False

    sess_prot = ""
    current_spduLen = 0
    current_spduNum = 0
    current_payloadLen = 0
    current_appID = 0
    signature_idx = 0
    signature_len = 0

    # Require LI = 0x01 and TI = 0x40
    if buf[0] == 0x01 and buf[1] == 0x40:
        # SI = 0xA1 for R-GOOSE
        if buf[2] == 0xA1:
            sess_prot = f"{namespace}GSE"
        # SI = 0xA2 for R-SV
        elif buf[2] == 0xA2:
            sess_prot = f"{namespace}SMV"
        else:
            print("[!] Error: Session protocol not implemented", file=sys.stderr)
            return False
    else:
        print("[!] Error: Application profile unknown", file=sys.stderr)
        return False

    if buf[3] != buf[5] + 2 or buf[4] != 0x80:
        print("[!] Error in Common Header", file=sys.stderr)
        return False

    if buf[14] != 0x00 or buf[15] != 0x01:
        print("[!] Error: Unexpected Session Protocol Version Number", file=sys.stderr)
        return False

    current_spduNum = struct.unpack('>I', buf[10:14])[0]

    if not (cbOut.prev_spduNum == 0 or (current_spduNum == 0 and cbOut.prev_spduNum == 0xFFFFFFFF)) and current_spduNum <= cbOut.prev_spduNum:
        return False

    current_spduLen = struct.unpack('>I', buf[6:10])[0]

    # Security Information skipped in this implementation

    current_payloadLen = struct.unpack('>I', buf[28:32])[0]
    signature_idx = 28 + current_payloadLen

    if buf[signature_idx] != 0x85:
        print("[!] Error in Signature", file=sys.stderr)
        return False

    signature_len = buf[signature_idx + 1]

    if 9 + current_spduLen != (signature_idx + 1 + signature_len):
        print("[!] Error: Inconsistent Lengths detected", file=sys.stderr)
        return False

    if not (buf[32] == 0x81 and sess_prot == f"{namespace}GSE") and not (buf[32] == 0x82 and sess_prot == f"{namespace}SMV"):
        print("[!] Error: Payload Type inconsistent with Session Identifier", file=sys.stderr)
        return False

    if buf[33] != 0:
        print("[!] Error: Incorrect value detected in 'Simulation' field", file=sys.stderr)
        return False

    if signature_idx != 36 + (buf[36] << 8) + buf[37]:
        print("[!] Error: APDU Length in Payload", file=sys.stderr)
        return False

    current_appID = struct.unpack('>H', buf[34:36])[0]

    if current_appID != int(cbOut.appID, 16):
        print("[!] Error: Incorrect appID in Payload", file=sys.stderr)
        print(current_appID, " != ",int(cbOut.appID, 16))
        return False

    if sess_prot == f"{namespace}GSE":
        if buf[38] != 0x61:
            print("[!] Error: GOOSE PDU Tag", file=sys.stderr)
            return False

        if 38 + buf[39] != signature_idx:
            print("[!] Error: GOOSE PDU Length", file=sys.stderr)
            return False

        tag_idx = 40
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x80:
            print("[!] Error: goCBRef Tag", file=sys.stderr)
            return False

        current_gocbRef = buf[len_idx + 1: len_idx + 1 + buf[len_idx]].decode()
        if current_gocbRef != cbOut.cbName:
            print("[!] Error: goCBRef mismatch", file=sys.stderr)
            return False

        tag_idx = (len_idx + 1 + buf[len_idx] + 6)
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x82:
            print("[!] Error: GOOSE datSet Tag", file=sys.stderr)
            print(buf[tag_idx] , " != 0x82")
            return False

        current_datSet = buf[len_idx + 1: len_idx + 1 + buf[len_idx]].decode()
        if current_datSet != cbOut.datSetName:
            print("[!] Error: datSet mismatch", file=sys.stderr)
            return False

        tag_idx = (len_idx + 1 + buf[len_idx])
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x83:
            print("[!] Error: GOOSE goID Tag", file=sys.stderr)
            return False

        current_goID = buf[len_idx + 1: len_idx + 1 + buf[len_idx]].decode()
        if current_goID != cbOut.cbName:
            print("[!] Error: goID mismatch", file=sys.stderr)
            return False

        tag_idx = (len_idx + 1 + buf[len_idx] + 10)
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x85:
            print("[!] Error: GOOSE stNum Tag", file=sys.stderr)
            return False
        print(len_idx," ",buf[len_idx])
        current_stNum = struct.unpack('>I', buf[len_idx + 1: len_idx + 1 + buf[len_idx]])[0]

        tag_idx = (len_idx + 1 + buf[len_idx])
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x86:
            print("[!] Error: GOOSE sqNum Tag", file=sys.stderr)
            return False

        current_sqNum = struct.unpack('>I', buf[len_idx + 1: len_idx + 1 + buf[len_idx]])[0]

        tag_idx = (len_idx + 1 + buf[len_idx])
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x87 or buf[len_idx] != 0x01 or buf[len_idx + 1] != 0x00:
            print("[!] Error: GOOSE test Tag/Length/Value", file=sys.stderr)
            return False

        tag_idx = (len_idx + 1 + buf[len_idx])
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x88 or buf[len_idx] != 0x01 or buf[len_idx + 1] != 0x01:
            print("[!] Error: GOOSE ConfRev Tag/Length/Value", file=sys.stderr)
            return False

        tag_idx = (len_idx + 1 + buf[len_idx])
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x89 or buf[len_idx] != 0x01 or buf[len_idx + 1] != 0x00:
            print("[!] Error: GOOSE ndsCom Tag/Length/Value", file=sys.stderr)
            return False

        tag_idx = (len_idx + 1 + buf[len_idx])
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x8A:
            print("[!] Error: GOOSE numDatSetEntries Tag", file=sys.stderr)
            return False
        current_numDatSetEntries = buf[len_idx + 1]

        tag_idx = (len_idx + 1 + buf[len_idx])
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0xAB:
            print("[!] Error: GOOSE allData Tag", file=sys.stderr)
            return False

        current_allData = list(buf[len_idx + 1: len_idx + 1 + buf[len_idx]])

        if current_stNum < cbOut.prev_stNum_Value:
            print("[!] Error: stNum", file=sys.stderr)
            return False

        if current_stNum != cbOut.prev_stNum_Value:
            if cbOut.prev_allData_Value == current_allData and current_stNum == cbOut.prev_stNum_Value + 1:
                print("[!] Error: stNum incremented but allData not changed", file=sys.stderr)
                return False

        if current_stNum == cbOut.prev_stNum_Value:
            if current_sqNum <= cbOut.prev_sqNum_Value and cbOut.prev_sqNum_Value != 0xFFFFFFFF:
                print("[!] Error: sqNum", file=sys.stderr)
                return False

            if current_sqNum != cbOut.prev_sqNum_Value:
                if cbOut.prev_sqNum_Value == 0xFFFFFFFF and current_sqNum == 0:
                    if current_allData == cbOut.prev_allData_Value:
                        print("[!] Error: sqNum reset but allData not changed", file=sys.stderr)
                        return False

                if current_allData != cbOut.prev_allData_Value:
                    print("[!] Error: allData not updated", file=sys.stderr)
                    print(current_allData , " != ", cbOut.prev_allData_Value)
                    return False

        if current_numDatSetEntries != cbOut.prev_numDatSetEntries:
            print("[!] Error: numDatSetEntries mismatch", file=sys.stderr)
            print(current_numDatSetEntries,'!=', cbOut.prev_numDatSetEntries)
            return False

        cbOut.prev_spduNum = current_spduNum
        cbOut.prev_stNum_Value = current_stNum
        cbOut.prev_sqNum_Value = current_sqNum
        cbOut.prev_allData_Value = current_allData
        cbOut.prev_numDatSetEntries = current_numDatSetEntries

    elif sess_prot == f"{namespace}SMV":
        if buf[38] != 0x60:
            print("[!] Error: SMV PDU Tag", file=sys.stderr)
            return False

        if 38 + buf[39] != signature_idx:
            print("[!] Error: SMV PDU Length", file=sys.stderr)
            return False

        tag_idx = 40
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x80:
            print("[!] Error: smpCnt Tag", file=sys.stderr)
            return False

        current_smpCnt = struct.unpack('>I', buf[len_idx + 1: len_idx + 1 + buf[len_idx]])[0]
        if current_smpCnt != cbOut.prev_smpCnt_Value:
            print("[!] Error: smpCnt mismatch", file=sys.stderr)
            return False

        tag_idx = (len_idx + 1 + buf[len_idx])
        len_idx = tag_idx + 1

        if buf[tag_idx] != 0x81:
            print("[!] Error: seqOfData Tag", file=sys.stderr)
            return False

        current_seqOfData = list(buf[len_idx + 1: len_idx + 1 + buf[len_idx]])
        if current_seqOfData != cbOut.prev_seqOfData_Value:
            print("[!] Error: seqOfData mismatch", file=sys.stderr)
            return False

        cbOut.prev_smpCnt_Value = current_smpCnt
        cbOut.prev_seqOfData_Value = current_seqOfData

    return True


# Constants

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
    print(sed_filename)
    vector_of_ctrl_blks = parse_sed(sed_filename)
    cbSubscribe = []
    for cb in vector_of_ctrl_blks:
        if ied_name in cb.subscribingIEDs:
            tmp_goose_sv_data = GooseSvData() 
            tmp_goose_sv_data.cbName = cb.cbName
            tmp_goose_sv_data.cbType = cb.cbType
            tmp_goose_sv_data.appID = cb.appID
            tmp_goose_sv_data.multicastIP = cb.multicastIP
            if cb.cbType == f'{namespace}GSE':
                tmp_goose_sv_data.datSetName = cb.datSetName

            cbSubscribe.append(tmp_goose_sv_data)

    print(len(cbSubscribe))
    if not cbSubscribe:
        print(f"{ied_name} has no Control Block(s) to subscribe to.")
        print(f"Please check configuration in {sed_filename}. Exiting program now...")
        return 1

    # sock = UdpSock()
    # diagnose(sock.is_good(), "Opening datagram socket for send")
    
    # # Create and configure socket
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # local_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # local_sock.bind(('', IEDUDPPORT))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    diagnose(sock is not None, "Opening datagram socket for receive")
    
    # Enable SO_REUSEADDR to allow multiple instances of this application to receive copies of the multicast datagrams
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        diagnose(True, "Setting SO_REUSEADDR")
    except Exception as e:
        diagnose(False, f"Setting SO_REUSEADDR: {e}")
    
    # Bind to the proper port number with the IP address specified as INADDR_ANY
    local_sock = ('', IEDUDPPORT)  # '' is equivalent to INADDR_ANY
    try:
        sock.bind(local_sock)
        diagnose(True, "Binding datagram socket")
    except Exception as e:
        diagnose(False, f"Binding datagram socket: {e}")



    for cb in cbSubscribe:
        group = ipaddress.ip_address(cb.multicastIP)
        mreq = struct.pack('4sl', group.packed, socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    ownXCBRposition = 1
    print("ok")
    while True:
        # print(sock.recvfrom(MAXBUFLEN))
        buf, addr = sock.recvfrom(MAXBUFLEN)
        numbytes = len(buf)
        print(f">> {numbytes} bytes received from {addr[0]}")
        # print(list(buf))
        print(cbSubscribe)
        for cb in cbSubscribe:
            # if valid_GSE_SMV(buf, numbytes, cb):
                if cb.cbType == f'{namespace}GSE':
                    print(f"Checked R-GOOSE OK\ncbName: {cb.cbName}")
                    print(f"\tallData = {{  {' '.join(f'{item:02x}' for item in cb.prev_allData_Value)} }}")
                    print(f"\tstNum = {cb.prev_stNum_Value} \tsqNum = {cb.prev_sqNum_Value} \t|"
                          f"\tSPDU Number (from Session Header) = {cb.prev_spduNum}")

                    if (cb.prev_allData_Value[0] == 0x83 and cb.prev_allData_Value[1] == 0x01):
                        if cb.prev_allData_Value[2] == 0:
                            print(f"[Simulation] Circuit-Breaker interlocking mechanism\n"
                                  f"\t{cb.datSetName} is Open.\n"
                                  f"\tOpen {ied_name}$XCBR as well.")
                            ownXCBRposition = 0
                        elif ownXCBRposition == 0:
                            print(f"[Simulation] Circuit-Breaker interlocking mechanism\n"
                                  f"\t{cb.datSetName} is Close.\n"
                                  f"\tClose {ied_name}$XCBR as well.")
                            ownXCBRposition = 1
                    else:
                        print("[!] GOOSE allData not recognised.")
                elif cb.cbType == f'{namespace}SMV':
                    print(f"cbName: {cb.cbName}")
                    print(f"smpCnt: {cb.prev_smpCnt_Value}")
                    print(f"Checked R-SV OK\nsequenceofdata = {{  {' '.join(f'{item:02x}' for item in cb.prev_seqOfData_Value)} }}")
                    # Add logic to convert sequence of data to IEEE float
                    seqOfData = []
                    dataBytes = []
                    for item in cb.prev_seqOfData_Value:
                        x = item
                        dataBytes.extend([((x >> i) & 1) for i in range(7, -1, -1)])
                        if len(dataBytes) == 32:
                            mantissa = convertToInt(dataBytes, 9, 31)
                            exponent = convertToInt(dataBytes, 1, 8)
                            sign = dataBytes[0]
                            float_value = struct.unpack('f', struct.pack('I', (sign << 31) | (exponent << 23) | mantissa))[0]
                            seqOfData.append(float_value)
                            dataBytes = []
                    print(' '.join(f"{data:.8f}" for data in seqOfData))
                break

if __name__ == "__main__":
    main(sys.argv)
