import xml.etree.ElementTree as ET

class ControlBlock:
    def __init__(self):
        self.hostIED = ""
        self.cbType = ""
        self.multicastIP = ""
        self.appID = ""
        self.vlanID = ""
        self.cbName = ""
        self.datSetName = ""
        self.datSetVector = []
        self.subscribingIEDs = []

def parse_sed(filename):
    vector_of_ctrl_blks = []

    tree = ET.parse(filename)
    root = tree.getroot()

    if root.tag != "SCL":
        print(f"Name of Root Node is not 'SCL'! Please check format of SED file: {filename}")
        exit(1)
    print(f"[*] Successfully parsed XML data in {filename}")
    print(f"Name of Root Node in SED file = {root.tag}\n")

    map_of_ld_with_cb = {}

    for comm in root.findall(".//Communication"):
        print(f"[*] Searching for Control Block(s) in <{comm.tag}> element...")

        for subnet in comm.findall("SubNetwork"):
            for ap in subnet.findall("ConnectedAP"):
                vector_of_LDs_with_CBs = []

                for cb in ap:
                    CB_tmp = ControlBlock()

                    if cb.tag in ["GSE", "SMV"]:
                        print(f"    {cb.tag} Control Block found in:")
                        print(f"    -> {subnet.tag}: {subnet.get('name')}")
                        print(f"        -> {ap.tag}: {ap.get('iedName')}")

                        ld_inst = cb.get("ldInst")
                        if ld_inst:
                            vector_of_LDs_with_CBs.append(ld_inst)
                        else:
                            print("    [!] But 'ldInst' is not found in Control Block's node")
                            exit(1)

                        CB_tmp.hostIED = ap.get("iedName")
                        CB_tmp.cbType = cb.tag

                        for address in cb.findall("Address/P"):
                            p_type = address.get("type")
                            if p_type == "IP":
                                CB_tmp.multicastIP = address.text
                            elif p_type == "APPID":
                                CB_tmp.appID = address.text
                            elif p_type == "VLAN-ID":
                                CB_tmp.vlanID = address.text

                        CB_tmp.cbName = cb.get("cbName")
                        vector_of_ctrl_blks.append(CB_tmp)

                if vector_of_LDs_with_CBs:
                    map_of_ld_with_cb[ap.get("iedName")] = vector_of_LDs_with_CBs
                    print(f"    Saved {len(vector_of_LDs_with_CBs)} LD(s) with CB(s) for IED {ap.get('iedName')} - to be checked later...\n")

    print(f"[*] Found a total of {len(vector_of_ctrl_blks)} Control Block(s).\n")

    for ied_name, ld_list in map_of_ld_with_cb.items():
        for ied in root.findall(".//IED"):
            if ied.get("name") == ied_name:
                print(f"[*] Checking Control Block(s) in IED name = {ied.get('name')}...")

                ap = ied.find("AccessPoint")

                for ldev in ap.findall("LDevice"):
                    if ld_list and ldev.get("inst") == ld_list[-1]:
                        cbName = ""
                        datSetName = ""
                        datSetVector = []

                        ln = ldev.find("LN0")

                        for cb in ln:
                            if cb.tag in ["GSEControl", "SampledValueControl"]:
                                cbName = cb.get("Name")
                                datSetName = cb.get("datSet")

                                for dataset in ln.findall("DataSet"):
                                    if dataset.get("name") == datSetName:
                                        for fcda in dataset.findall("FCDA"):
                                            currentCyber = f"{ied.get('name')}.{fcda.get('lnClass')}.{fcda.get('doName')}.{fcda.get('daName')}"
                                            datSetVector.append(currentCyber)

                                if not datSetVector:
                                    print("\t[!] Couldn't find a matching datSet Name in LN Node as the Control Block's.")
                                    exit(1)

                                for ctrl_blk in vector_of_ctrl_blks:
                                    if (ctrl_blk.hostIED == ied_name and ctrl_blk.cbName == cbName):
                                        prefix = f"{ldev.get('inst')}/{ln.get('lnClass')}."
                                        cbName = prefix + cbName
                                        datSetName = prefix + datSetName

                                        ctrl_blk.cbName = cbName
                                        ctrl_blk.datSetName = datSetName
                                        ctrl_blk.datSetVector = datSetVector

                                        for subscribing in cb.findall("IEDName"):
                                            ctrl_blk.subscribingIEDs.append(subscribing.text)

                                        break

                        ld_list.pop()
                        if not ld_list:
                            break

    print("\n[*] Finished parsing SED file for Control Blocks.\n")
    return vector_of_ctrl_blks
