Fortinet_File=open("/Users/kashan/Desktop/ICT Project A/RuleFile/fortinet.conf","r")
Lines=Fortinet_File.readlines()
Fortinet_File.close()

Addresses={}
Rules={}
Check1=False
Check2=False
Check3=False

for Line in Lines:
    Line=Line.strip()

    if Line=="config firewall address":
        Check1=True
        Check2=False

    elif Line=="config firewall policy":
        Check2=True
        Check1=False

    elif(Check1==True):
        if(Line.startswith("edit")):
            parts=Line.split('"')
            if len(parts)>1:
                Temp_Address_Name=parts[1]
            else:
                Temp_Address_Name=Line.split()[1]
            Addresses[Temp_Address_Name]={}
        elif(Line.startswith("set subnet")):
            Line=Line.split()
            Addresses[Temp_Address_Name]["IP"]=Line[2]
            Addresses[Temp_Address_Name]["Subnet"]=Line[3]

    elif(Check2==True):
        if(Line.startswith("edit")):
            Temp_Rule={}                               
            Temp_Rule["Rule_Number"]=Line.split()[1]
        elif(Line.startswith("set name")):
            parts=Line.split('"')
            if len(parts)>1 and parts[1]!='':
                Temp_Rule["Rule_Name"]=parts[1]
        elif(Line.startswith("set srcintf")):
            parts=Line.split('"')
            if len(parts)>1 and parts[1]!='':
                Temp_Rule["Source_Zone"]=parts[1]
        elif(Line.startswith("set dstintf")):
            parts=Line.split('"')
            if len(parts)>1 and parts[1]!='':
                Temp_Rule["Destination_Zone"]=parts[1]
        elif(Line.startswith("set srcaddr")):
            parts=Line.split('"')
            if len(parts)>1 and parts[1]!='':
                Temp_Rule["Source_Device"]=parts[1]
        elif(Line.startswith("set dstaddr")):
            parts=Line.split('"')
            if len(parts)>1 and parts[1]!='':
                Temp_Rule["Destination_Device"]=parts[1]
        elif(Line.startswith("set service")):
            parts=Line.split('"')
            if len(parts)>1 and parts[1]!='':
                Temp_Rule["Application"]=parts[1]
        elif(Line.startswith("set action")):
            Temp_Rule["Action"]=Line.split()[2]
        elif(Line=="next"):
            if "Rule_Name" not in Temp_Rule:
                Temp_Rule["Rule_Name"]=f"Rule_{Temp_Rule.get('Rule_Number','Unknown')}"
            if all(k in Temp_Rule for k in ["Rule_Number","Rule_Name","Source_Zone","Destination_Zone","Source_Device","Destination_Device","Application","Action"]):
                Rule_Name=Temp_Rule["Rule_Name"]
                Rules[Rule_Name]=Temp_Rule
            Temp_Rule={}                              

Rules_List=list(Rules.values())

import xml.etree.cElementTree as ET

new_file_root_element=ET.Element("Firewall")
for Rule_Name,Rule_Values in Rules.items():
    child_element=ET.SubElement(new_file_root_element,"FortiGate_Rule")
    child_element.set("id",str(Rule_Values["Rule_Number"]))

    sub_child_name_element=ET.SubElement(child_element,"Rule_Name")
    sub_child_name_element.text=Rule_Values["Rule_Name"]

    sub_child_source_zone_element=ET.SubElement(child_element,"Source_Zone")
    sub_child_source_zone_element.text=Rule_Values["Source_Zone"]

    sub_child_destination_zone_element=ET.SubElement(child_element,"Destination_Zone")
    sub_child_destination_zone_element.text=Rule_Values["Destination_Zone"]

    sub_child_source_device_element=ET.SubElement(child_element,"Source_Device")
    sub_child_source_device_element.text=Rule_Values["Source_Device"]

    sub_child_destination_device_element=ET.SubElement(child_element,"Destination_Device")
    sub_child_destination_device_element.text=Rule_Values["Destination_Device"]

    sub_child_application_element=ET.SubElement(child_element,"Application")
    sub_child_application_element.text=Rule_Values["Application"]

    sub_child_action_element=ET.SubElement(child_element,"Action")
    sub_child_action_element.text=Rule_Values["Action"]

tree=ET.ElementTree(new_file_root_element)
ET.indent(tree,space="  ",level=0)
tree.write("normalized_rules.xml")

def Redundancy_Check(rule1,rule2):
    if( (rule1["Source_Zone"]==rule2["Source_Zone"]) and (rule1["Destination_Zone"]==rule2["Destination_Zone"]) 
       and (rule1["Source_Device"]==rule2["Source_Device"]) and (rule1["Destination_Device"]==rule2["Destination_Device"])
       and (rule1["Application"]==rule2["Application"]) and (rule1["Action"]==rule2["Action"]) ):
        return True 
    return False


def Is_Shadowed(rule1,rule2):
    if( ( (rule1["Source_Zone"]==rule2["Source_Zone"]) or (rule1["Source_Zone"]=="any") ) and 
        ( (rule1["Destination_Zone"]==rule2["Destination_Zone"]) or (rule1["Destination_Zone"]=="any") ) and 
        ( (rule1["Source_Device"]==rule2["Source_Device"]) or (rule1["Source_Device"]=="all") ) and 
        ( (rule1["Destination_Device"]==rule2["Destination_Device"]) or (rule1["Destination_Device"]=="all") ) and 
        ( (rule1["Application"]==rule2["Application"]) or (rule1["Application"]=="ALL") ) ):
        return True
    return False


def Collision_Check(rule1,rule2):
    if( (rule1["Source_Zone"]==rule2["Source_Zone"]) and (rule1["Destination_Zone"]==rule2["Destination_Zone"]) 
        and (rule1["Source_Device"]==rule2["Source_Device"]) and (rule1["Destination_Device"]==rule2["Destination_Device"])
        and (rule1["Application"]==rule2["Application"]) and (rule1["Action"]!=rule2["Action"]) ):
            return True 
    return False


counter1=0
redundant_rules=set()
shadowed_rules=set()
collision_rules=set()

while(counter1<len(Rules_List)):
    counter2=counter1+1
    while(counter2<len(Rules_List)):
        rule1=Rules_List[counter1]
        rule2=Rules_List[counter2]
        
        if(Redundancy_Check(rule1,rule2)):
            if rule2["Rule_Number"] not in redundant_rules:
                print(f"[REDUNDANT]")
                print(f"Rule {rule2['Rule_Number']} - {rule2['Rule_Name']} is redundant")
                print(f"Reason: Identical to Rule {rule1['Rule_Number']} - {rule1['Rule_Name']} which came earlier")
                print(f"Action: Remove Rule {rule2['Rule_Number']} - it adds no value")
                print(f"---")
                redundant_rules.add(rule2["Rule_Number"])

        if(Is_Shadowed(rule1,rule2)):
            if rule2["Rule_Number"] not in shadowed_rules:
                print(f"[SHADOW]")
                print(f"Rule {rule2['Rule_Number']} - {rule2['Rule_Name']} is shadowed")
                print(f"Reason: Rule {rule1['Rule_Number']} - {rule1['Rule_Name']} came earlier and covers same traffic")
                print(f"Action: Remove Rule {rule2['Rule_Number']} - it will never be reached")
                print(f"---")
                shadowed_rules.add(rule2["Rule_Number"])
        
        if(Collision_Check(rule1,rule2)):
            if rule2["Rule_Number"] not in collision_rules:
                print(f"[Collision]")
                print(f"Rule {rule2['Rule_Number']} - {rule2['Rule_Name']} has collision")
                print(f"Reason: Rule {rule1['Rule_Number']} - {rule1['Rule_Name']} covers same traffic but different action")
                print(f"Action: Remove Rule {rule2['Rule_Number']} - it has a opposite action")
                print(f"---")
                collision_rules.add(rule2["Rule_Number"])
        
        counter2+=1
    counter1+=1


redundant_file_root_element=ET.Element("Firewall")
for rule in Rules_List:
    if rule["Rule_Number"] in redundant_rules:
        child_element=ET.SubElement(redundant_file_root_element,"FortiGate_Rule")
        child_element.set("id",str(rule["Rule_Number"]))
        sub_child_name_element=ET.SubElement(child_element,"Rule_Name")
        sub_child_name_element.text=rule["Rule_Name"]
        sub_child_source_zone_element=ET.SubElement(child_element,"Source_Zone")
        sub_child_source_zone_element.text=rule["Source_Zone"]
        sub_child_destination_zone_element=ET.SubElement(child_element,"Destination_Zone")
        sub_child_destination_zone_element.text=rule["Destination_Zone"]
        sub_child_source_device_element=ET.SubElement(child_element,"Source_Device")
        sub_child_source_device_element.text=rule["Source_Device"]
        sub_child_destination_device_element=ET.SubElement(child_element,"Destination_Device")
        sub_child_destination_device_element.text=rule["Destination_Device"]
        sub_child_application_element=ET.SubElement(child_element,"Application")
        sub_child_application_element.text=rule["Application"]
        sub_child_action_element=ET.SubElement(child_element,"Action")
        sub_child_action_element.text=rule["Action"]
        sub_child_status_element=ET.SubElement(child_element,"Status")
        sub_child_status_element.text="REDUNDANT"
redundant_tree=ET.ElementTree(redundant_file_root_element)
ET.indent(redundant_tree,space="  ",level=0)
redundant_tree.write("redundant_rules.xml")


shadow_file_root_element=ET.Element("Firewall")
for rule in Rules_List:
    if rule["Rule_Number"] in shadowed_rules:
        child_element=ET.SubElement(shadow_file_root_element,"FortiGate_Rule")
        child_element.set("id",str(rule["Rule_Number"]))
        sub_child_name_element=ET.SubElement(child_element,"Rule_Name")
        sub_child_name_element.text=rule["Rule_Name"]
        sub_child_source_zone_element=ET.SubElement(child_element,"Source_Zone")
        sub_child_source_zone_element.text=rule["Source_Zone"]
        sub_child_destination_zone_element=ET.SubElement(child_element,"Destination_Zone")
        sub_child_destination_zone_element.text=rule["Destination_Zone"]
        sub_child_source_device_element=ET.SubElement(child_element,"Source_Device")
        sub_child_source_device_element.text=rule["Source_Device"]
        sub_child_destination_device_element=ET.SubElement(child_element,"Destination_Device")
        sub_child_destination_device_element.text=rule["Destination_Device"]
        sub_child_application_element=ET.SubElement(child_element,"Application")
        sub_child_application_element.text=rule["Application"]
        sub_child_action_element=ET.SubElement(child_element,"Action")
        sub_child_action_element.text=rule["Action"]
        sub_child_status_element=ET.SubElement(child_element,"Status")
        sub_child_status_element.text="SHADOWED"
shadow_tree=ET.ElementTree(shadow_file_root_element)
ET.indent(shadow_tree,space="  ",level=0)
shadow_tree.write("shadowed_rules.xml")


collision_file_root_element=ET.Element("Firewall")
for rule in Rules_List:
    if rule["Rule_Number"] in collision_rules:
        child_element=ET.SubElement(collision_file_root_element,"FortiGate_Rule")
        child_element.set("id",str(rule["Rule_Number"]))
        sub_child_name_element=ET.SubElement(child_element,"Rule_Name")
        sub_child_name_element.text=rule["Rule_Name"]
        sub_child_source_zone_element=ET.SubElement(child_element,"Source_Zone")
        sub_child_source_zone_element.text=rule["Source_Zone"]
        sub_child_destination_zone_element=ET.SubElement(child_element,"Destination_Zone")
        sub_child_destination_zone_element.text=rule["Destination_Zone"]
        sub_child_source_device_element=ET.SubElement(child_element,"Source_Device")
        sub_child_source_device_element.text=rule["Source_Device"]
        sub_child_destination_device_element=ET.SubElement(child_element,"Destination_Device")
        sub_child_destination_device_element.text=rule["Destination_Device"]
        sub_child_application_element=ET.SubElement(child_element,"Application")
        sub_child_application_element.text=rule["Application"]
        sub_child_action_element=ET.SubElement(child_element,"Action")
        sub_child_action_element.text=rule["Action"]
        sub_child_status_element=ET.SubElement(child_element,"Status")
        sub_child_status_element.text="Collision"
redundant_tree=ET.ElementTree(collision_file_root_element)
ET.indent(redundant_tree,space="  ",level=0)
redundant_tree.write("collision_rules.xml")