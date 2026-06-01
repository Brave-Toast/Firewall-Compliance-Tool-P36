import re
import random
from datetime import datetime

EXT_CLIENT="10.0.1.10"
EXT_NET="10.0.1.0/24"
WEB_SERVER="10.0.50.10"
DMZ_NET="10.0.50.0/24"

SERVICES=[
    ("tcp","80","web-browsing","policy-violation","flow:established,to_server; "),
    ("tcp","443","ssl","policy-violation","flow:established,to_server; "),
    ("tcp","22","ssh","attempted-admin","flow:to_server; "),
    ("tcp","3389","rdp","attempted-admin","flow:to_server; "),
    ("tcp","445","smb","attempted-user","flow:to_server; "),
    ("tcp","1433","mssql","attempted-admin",""),
    ("tcp","3306","mysql","attempted-admin","flow:to_server; "),
    ("tcp","5432","postgresql","attempted-admin","flow:established; "),
    ("tcp","21","ftp","policy-violation","flow:to_client; "),
    ("udp","53","dns","policy-violation",""),
    ("udp","123","ntp","misc-activity",""),
    ("udp","161","snmp","attempted-recon",""),
    ("icmp","any","icmp","misc-activity",""),
    ("ip","any","any-traffic","misc-activity",""),
]

SOURCES=[EXT_CLIENT,EXT_NET,WEB_SERVER,DMZ_NET]
DESTINATIONS=[EXT_CLIENT,EXT_NET,WEB_SERVER,DMZ_NET,"any"]
ACTIONS=["pass","drop","alert"]

def Get_User_Input():
    print("=== Suricata Rule Generator - P36 ===")
    Total_Rules=int(input("How many rules to generate? "))
    Redundant_Pct=int(input("Redundancy percentage (e.g. 10 for 10%)? "))
    Shadow_Pct=int(input("Shadow percentage (e.g. 10 for 10%)? "))
    Collision_Pct=int(input("Collision percentage (e.g. 5 for 5%)? "))
    Seed=int(input("Random seed (e.g. 1)? "))
    Output_File=input("Output filename (e.g. suricata_generated.rules)? ")
    return Total_Rules,Redundant_Pct,Shadow_Pct,Collision_Pct,Seed,Output_File

def Calculate_Counts(Total_Rules,Redundant_Pct,Shadow_Pct,Collision_Pct):
    Redundant_Count=int(Total_Rules*Redundant_Pct/100)
    Shadow_Pairs=int(Total_Rules*Shadow_Pct/100)//2
    Collision_Pairs=int(Total_Rules*Collision_Pct/100)//2
    Shadow_Count=Shadow_Pairs*2
    Collision_Count=Collision_Pairs*2
    Normal_Count=Total_Rules-Redundant_Count-Shadow_Count-Collision_Count
    return Normal_Count,Redundant_Count,Shadow_Pairs,Collision_Pairs

def Make_Rule(Sid,Action,Proto,Src,Dst,Port,Flow_Opts,Classtype,Msg):
    return f'{Action} {Proto} {Src} any -> {Dst} {Port} (msg:"{Msg}"; {Flow_Opts}classtype:{Classtype}; sid:{Sid}; rev:1;)'

def Generate_Normal_Rules(Count,Sid_Start,Seed):
    random.seed(Seed)
    Rules=[]
    Sid=Sid_Start
    for I in range(Count):
        Proto,Port,App,Classtype,Flow_Opts=random.choice(SERVICES)
        Src=random.choice(SOURCES)
        Dst=random.choice(DESTINATIONS)
        Action=random.choice(ACTIONS)
        Msg=f"P36-Normal-Rule-{I+1}-{App}-{Action}"
        Rules.append(Make_Rule(Sid,Action,Proto,Src,Dst,Port,Flow_Opts,Classtype,Msg))
        Sid+=1
    return Rules,Sid

def Generate_Redundant_Rules(Normal_Rules,Count,Sid_Start):
    Rules=[]
    Sid=Sid_Start
    for I in range(Count):
        Original=random.choice(Normal_Rules)
        Parts=Original.split()
        Action=Parts[0]
        Proto=Parts[1]
        Src=Parts[2]
        Dst=Parts[5]
        Port=Parts[6]
        Flow_Match=re.search(r'flow:[^;]+;',Original)
        Flow_Opts=Flow_Match.group(0)+" " if Flow_Match else ""
        Class_Match=re.search(r'classtype:([^;]+);',Original)
        Classtype=Class_Match.group(1) if Class_Match else "misc-activity"
        Msg=f"P36-Redundant-Rule-{I+1}-REDUNDANT"
        Rules.append(Make_Rule(Sid,Action,Proto,Src,Dst,Port,Flow_Opts,Classtype,Msg))
        Sid+=1
    return Rules,Sid

def Generate_Shadow_Pairs(Normal_Rules,Pairs,Sid_Start):
    Valid_Templates=[R for R in Normal_Rules if R.split()[2]!="any"]
    Pairs_List=[]
    Sid=Sid_Start
    for I in range(Pairs):
        Original=random.choice(Valid_Templates)
        Parts=Original.split()
        Action=Parts[0]
        Proto=Parts[1]
        Src=Parts[2]
        Dst=Parts[5]
        Port=Parts[6]
        Class_Match=re.search(r'classtype:([^;]+);',Original)
        Classtype=Class_Match.group(1) if Class_Match else "misc-activity"
        Broad_Rule=Make_Rule(Sid,Action,Proto,"any",Dst,Port,"",Classtype,f"P36-Shadow-Broad-{I+1}")
        Sid+=1
        Specific_Rule=Make_Rule(Sid,Action,Proto,Src,Dst,Port,"",Classtype,f"P36-Shadow-Specific-{I+1}-SHADOWED")
        Sid+=1
        Pairs_List.append((Broad_Rule,Specific_Rule))
    return Pairs_List,Sid

def Generate_Collision_Pairs(Normal_Rules,Pairs,Sid_Start):
    Pairs_List=[]
    Sid=Sid_Start
    for I in range(Pairs):
        Original=random.choice(Normal_Rules)
        Parts=Original.split()
        Action=Parts[0]
        Proto=Parts[1]
        Src=Parts[2]
        Dst=Parts[5]
        Port=Parts[6]
        Class_Match=re.search(r'classtype:([^;]+);',Original)
        Classtype=Class_Match.group(1) if Class_Match else "misc-activity"
        Opp_Action="drop" if Action in ["pass","alert"] else "pass"
        Rule_A=Make_Rule(Sid,Action,Proto,Src,Dst,Port,"",Classtype,f"P36-Collision-{I+1}-{Action}")
        Sid+=1
        Rule_B=Make_Rule(Sid,Opp_Action,Proto,Src,Dst,Port,"",Classtype,f"P36-Collision-{I+1}-{Opp_Action}-CONFLICT")
        Sid+=1
        Pairs_List.append((Rule_A,Rule_B))
    return Pairs_List,Sid

def Inject_Pairs(Normal_Rules,Pairs_List):
    Rules=list(Normal_Rules)
    for Pair in Pairs_List:
        Insert_At=random.randint(0,len(Rules))
        Rules.insert(Insert_At,Pair[1])
        Rules.insert(Insert_At,Pair[0])
    return Rules

def Write_Rules(Rules,Output_File):
    Header=f"# Suricata Rule Generator - ICT30017 P36\n# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n# Total rules: {len(Rules)}\n"
    with open(Output_File,"w") as F:
        F.write(Header+"\n")
        for Rule in Rules:
            F.write(Rule+"\n")
    print(f"Written {len(Rules)} rules to {Output_File}")


def Push_To_Suricata(Rules_File,Container_Name="ngfw_suricata",Container_Path="/usr/share/suricata/rules/suricata_generated.rules"):
    import subprocess
    Result=subprocess.run(
        ["docker","cp",Rules_File,f"{Container_Name}:{Container_Path}"],
        capture_output=True,text=True
    )
    if Result.returncode==0:
        print(f"Rules pushed to container successfully")
        return True
    else:
        print(f"Error pushing rules: {Result.stderr}")
        return False
    
if __name__=="__main__":
    Total_Rules,Redundant_Pct,Shadow_Pct,Collision_Pct,Seed,Output_File=Get_User_Input()
    if Redundant_Pct+Shadow_Pct+Collision_Pct>=100:
        print("Error: percentages add up to 100 or more")
    else:
        Normal_Count,Redundant_Count,Shadow_Pairs,Collision_Pairs=Calculate_Counts(Total_Rules,Redundant_Pct,Shadow_Pct,Collision_Pct)
        print(f"Normal: {Normal_Count} Redundant: {Redundant_Count} Shadow: {Shadow_Pairs*2} Collision: {Collision_Pairs*2}")
        Normal_Rules,Next_Sid=Generate_Normal_Rules(Normal_Count,9000001,Seed)
        Redundant_Rules,Next_Sid=Generate_Redundant_Rules(Normal_Rules,Redundant_Count,Next_Sid)
        Shadow_Pairs_List,Next_Sid=Generate_Shadow_Pairs(Normal_Rules,Shadow_Pairs,Next_Sid)
        Collision_Pairs_List,Next_Sid=Generate_Collision_Pairs(Normal_Rules,Collision_Pairs,Next_Sid)
        random.shuffle(Normal_Rules)
        for Rule in Redundant_Rules:
            Insert_At=random.randint(0,max(0,len(Normal_Rules)-1))
            Normal_Rules.insert(Insert_At,Rule)
        All_Rules=Inject_Pairs(Normal_Rules,Shadow_Pairs_List+Collision_Pairs_List)
        Write_Rules(All_Rules,Output_File)
        Push_To_Suricata(Output_File)