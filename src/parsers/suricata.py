import re
import xml.etree.ElementTree as ET

class SuricataParser:

    @classmethod
    def parse_from_file(cls,File_Path):
        return [Dict_To_FirewallRule(R) for R in Parse_Rules(File_Path)]

    @classmethod
    def parse_from_text(cls,Text):
        import tempfile,os
        Temp=tempfile.NamedTemporaryFile(mode="w",suffix=".rules",delete=False)
        Temp.write(Text)
        Temp.close()
        Rules=Parse_Rules(Temp.name)
        os.unlink(Temp.name)
        return [Dict_To_FirewallRule(R) for R in Rules]

def Read_From_File(Filename):
    with open(Filename,"r") as File:
        return File.readlines()

def Parse_Rules(Filename):
    Rules=[]
    Lines=Read_From_File(Filename)
    for Line in Lines:
        Line=Line.strip()
        if not Line:
            continue
        if Line.startswith("#"):
            continue
        if "(" not in Line:
            continue
        Header_Block,Options_Block=Line.split("(",1)
        Options_Block=Options_Block.rstrip(");")
        Header_Parts=Header_Block.split()
        if len(Header_Parts)<7:
            continue
        Action=Header_Parts[0]
        Protocol=Header_Parts[1]
        Src_IP=Header_Parts[2]
        Src_Port=Header_Parts[3]
        Dst_IP=Header_Parts[5]
        Dst_Port=Header_Parts[6]
        Msg=None
        Sid=None
        Msg_Match=re.search(r'msg\s*:\s*"([^"]+)"',Options_Block)
        if Msg_Match:
            Msg=Msg_Match.group(1)
        Sid_Match=re.search(r'sid\s*:\s*(\d+)',Options_Block)
        if Sid_Match:
            Sid=Sid_Match.group(1)
        if Sid:
            Rule_Data={
                "Rule_Number":Sid,
                "Rule_Name":Msg,
                "Source_Zone":"any",
                "Destination_Zone":"any",
                "Source_Device":Src_IP,
                "Destination_Device":Dst_IP,
                "Protocol":Protocol,
                "Src_Port":Src_Port,
                "Dst_Port":Dst_Port,
                "Action":Action
            }
            Rules.append(Rule_Data)
    return Rules

def Dict_To_FirewallRule(Rule_Dict):
    try:
        from ..schema import FirewallRule,Action
    except ImportError:
        return Rule_Dict
    Action_Map={
        "pass":Action.allow,
        "alert":Action.allow,
        "drop":Action.deny,
        "reject":Action.deny
    }
    return FirewallRule(
        id=f"suricata-{Rule_Dict['Rule_Number']}",
        vendor="suricata",
        name=Rule_Dict["Rule_Name"],
        source_zones=[Rule_Dict["Source_Zone"]],
        destination_zones=[Rule_Dict["Destination_Zone"]],
        source_addresses=[Rule_Dict["Source_Device"]],
        destination_addresses=[Rule_Dict["Destination_Device"]],
        application=Rule_Dict["Protocol"],
        service=f"{Rule_Dict['Protocol']}/{Rule_Dict['Dst_Port']}",
        action=Action_Map.get(Rule_Dict["Action"].lower(),Action.deny),
        enabled=True,
        logging=Rule_Dict["Action"].lower()=="alert",
        metadata={"raw_action":Rule_Dict["Action"],"src_port":Rule_Dict["Src_Port"],"dst_port":Rule_Dict["Dst_Port"]}
    )

def Pull_From_Suricata(Container_Name="ngfw_suricata",Container_Path="/usr/share/suricata/rules/suricata_generated.rules",Output_File="pulled_rules.rules"):
    import subprocess
    Result=subprocess.run(
        ["docker","cp",f"{Container_Name}:{Container_Path}",Output_File],
        capture_output=True,text=True
    )
    if Result.returncode==0:
        print(f"Rules pulled from container to {Output_File}")
        return Output_File
    else:
        print(f"Error pulling rules: {Result.stderr}")
        return None

def Parse_Port_To_Set(Port_Str):
    Clean_Str="".join(Port_Str.split()).strip("[]")
    if Clean_Str=="any":
        return set(range(0,65536))
    Ports=set()
    for Part in Clean_Str.split(","):
        if ":" in Part:
            Start,End=Part.split(":")
            Start=int(Start.strip()) if Start.strip() else 0
            End=int(End.strip()) if End.strip() else 65535
            Ports.update(range(Start,End+1))
        else:
            if Part.strip():
                Ports.add(int(Part.strip()))
    return Ports

def Redundancy_Check(Rule1,Rule2):
    R1_Dst_Ports=Parse_Port_To_Set(Rule1["Dst_Port"])
    R2_Dst_Ports=Parse_Port_To_Set(Rule2["Dst_Port"])
    R1_Src_Ports=Parse_Port_To_Set(Rule1["Src_Port"])
    R2_Src_Ports=Parse_Port_To_Set(Rule2["Src_Port"])
    if(Rule1["Source_Device"]==Rule2["Source_Device"] and
       Rule1["Destination_Device"]==Rule2["Destination_Device"] and
       Rule1["Protocol"]==Rule2["Protocol"] and
       R1_Dst_Ports==R2_Dst_Ports and
       R1_Src_Ports==R2_Src_Ports and
       Rule1["Action"]==Rule2["Action"]):
        return True
    return False

def Is_Shadowed(Rule1,Rule2):
    Protocol_Shadowed=(Rule1["Protocol"]=="ip" or Rule1["Protocol"]==Rule2["Protocol"])
    Source_Shadowed=(Rule1["Source_Device"]=="any" or Rule1["Source_Device"]==Rule2["Source_Device"])
    Dest_Shadowed=(Rule1["Destination_Device"]=="any" or Rule1["Destination_Device"]==Rule2["Destination_Device"])
    R1_Dst_Ports=Parse_Port_To_Set(Rule1["Dst_Port"])
    R2_Dst_Ports=Parse_Port_To_Set(Rule2["Dst_Port"])
    R1_Src_Ports=Parse_Port_To_Set(Rule1["Src_Port"])
    R2_Src_Ports=Parse_Port_To_Set(Rule2["Src_Port"])
    Dst_Port_Shadowed=R2_Dst_Ports.issubset(R1_Dst_Ports)
    Src_Port_Shadowed=R2_Src_Ports.issubset(R1_Src_Ports)
    return Protocol_Shadowed and Source_Shadowed and Dest_Shadowed and Dst_Port_Shadowed and Src_Port_Shadowed

def Collision_Check(Rule1,Rule2):
    R1_Dst_Ports=Parse_Port_To_Set(Rule1["Dst_Port"])
    R2_Dst_Ports=Parse_Port_To_Set(Rule2["Dst_Port"])
    R1_Src_Ports=Parse_Port_To_Set(Rule1["Src_Port"])
    R2_Src_Ports=Parse_Port_To_Set(Rule2["Src_Port"])
    if(Rule1["Source_Device"]==Rule2["Source_Device"] and
       Rule1["Destination_Device"]==Rule2["Destination_Device"] and
       Rule1["Protocol"]==Rule2["Protocol"] and
       R1_Dst_Ports==R2_Dst_Ports and
       R1_Src_Ports==R2_Src_Ports and
       Rule1["Action"]!=Rule2["Action"]):
        return True
    return False

def Write_XML(Rules_List,Status,Output_File):
    Root=ET.Element("Firewall")
    for Rule in Rules_List:
        Child=ET.SubElement(Root,"Suricata_Rule")
        Child.set("id",str(Rule["Rule_Number"]))
        Sub_Name=ET.SubElement(Child,"Rule_Name")
        Sub_Name.text=Rule["Rule_Name"]
        Sub_Source_Zone=ET.SubElement(Child,"Source_Zone")
        Sub_Source_Zone.text=Rule["Source_Zone"]
        Sub_Dest_Zone=ET.SubElement(Child,"Destination_Zone")
        Sub_Dest_Zone.text=Rule["Destination_Zone"]
        Sub_Src_Device=ET.SubElement(Child,"Source_Device")
        Sub_Src_Device.text=Rule["Source_Device"]
        Sub_Dst_Device=ET.SubElement(Child,"Destination_Device")
        Sub_Dst_Device.text=Rule["Destination_Device"]
        Sub_Protocol=ET.SubElement(Child,"Protocol")
        Sub_Protocol.text=Rule["Protocol"]
        Sub_Src_Port=ET.SubElement(Child,"Src_Port")
        Sub_Src_Port.text=Rule["Src_Port"]
        Sub_Dst_Port=ET.SubElement(Child,"Dst_Port")
        Sub_Dst_Port.text=Rule["Dst_Port"]
        Sub_Action=ET.SubElement(Child,"Action")
        Sub_Action.text=Rule["Action"]
        Sub_Status=ET.SubElement(Child,"Status")
        Sub_Status.text=Status
    Tree=ET.ElementTree(Root)
    ET.indent(Tree,space="  ",level=0)
    Tree.write(Output_File,encoding="unicode",xml_declaration=True)

def Run_Parser(Filename):
    Rules_List=Parse_Rules(Filename)
    Counter1=0
    Redundant_Rules=set()
    Shadowed_Rules=set()
    Collision_Rules=set()
    while Counter1<len(Rules_List):
        Counter2=Counter1+1
        while Counter2<len(Rules_List):
            Rule1=Rules_List[Counter1]
            Rule2=Rules_List[Counter2]
            if Redundancy_Check(Rule1,Rule2):
                if Rule2["Rule_Number"] not in Redundant_Rules:
                    print(f"[REDUNDANT]")
                    print(f"Rule {Rule2['Rule_Number']} - {Rule2['Rule_Name']} is redundant")
                    print(f"Reason: Identical to Rule {Rule1['Rule_Number']} - {Rule1['Rule_Name']} which came earlier")
                    print(f"Action: Remove Rule {Rule2['Rule_Number']} - it adds no value")
                    print(f"---")
                    Redundant_Rules.add(Rule2["Rule_Number"])
            if Is_Shadowed(Rule1,Rule2) and Rule1["Action"]==Rule2["Action"]:
                if Rule2["Rule_Number"] not in Shadowed_Rules:
                    print(f"[SHADOW]")
                    print(f"Rule {Rule2['Rule_Number']} - {Rule2['Rule_Name']} is shadowed")
                    print(f"Reason: Rule {Rule1['Rule_Number']} - {Rule1['Rule_Name']} came earlier and covers same traffic")
                    print(f"Action: Remove Rule {Rule2['Rule_Number']} - it will never be reached")
                    print(f"---")
                    Shadowed_Rules.add(Rule2["Rule_Number"])
            if Collision_Check(Rule1,Rule2):
                if Rule2["Rule_Number"] not in Collision_Rules:
                    print(f"[COLLISION]")
                    print(f"Rule {Rule2['Rule_Number']} - {Rule2['Rule_Name']} has a collision")
                    print(f"Reason: Rule {Rule1['Rule_Number']} - {Rule1['Rule_Name']} covers same traffic but different action")
                    print(f"Action: Review Rule {Rule2['Rule_Number']} - conflicting actions detected")
                    print(f"---")
                    Collision_Rules.add(Rule2["Rule_Number"])
            Counter2+=1
        Counter1+=1
    Redundant_List=[]
    Shadowed_List=[]
    Collision_List=[]
    for Rule in Rules_List:
        if Rule["Rule_Number"] in Redundant_Rules:
            Redundant_List.append(Rule)
        if Rule["Rule_Number"] in Shadowed_Rules:
            Shadowed_List.append(Rule)
        if Rule["Rule_Number"] in Collision_Rules:
            Collision_List.append(Rule)
    Write_XML(Rules_List,"OK","Suricata_normalized_rules.xml")
    Write_XML(Redundant_List,"REDUNDANT","Suricata_redundant_rules.xml")
    Write_XML(Shadowed_List,"SHADOWED","Suricata_shadowed_rules.xml")
    Write_XML(Collision_List,"COLLISION","Suricata_collision_rules.xml")
    print(f"Total Rules: {len(Rules_List)}")
    print(f"Redundant: {len(Redundant_List)}")
    print(f"Shadowed: {len(Shadowed_List)}")
    print(f"Collisions: {len(Collision_List)}")

if __name__=="__main__":
    import sys
    if len(sys.argv)>1:
        Rules_File=sys.argv[1]
    else:
        Rules_File=Pull_From_Suricata()
    if Rules_File:
        Run_Parser(Rules_File)