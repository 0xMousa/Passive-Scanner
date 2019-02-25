from scapy.all import *

def ttlFingerprint(ttlValue):
    ttl = {64: "Linux", 128: "Windows", 255: "IOS"}
    if ttlValue in ttl:
        return ttl[ttlValue]
    else:
        return "UNKOWN"

def appproto(port,proto):
    proto = proto.lower()
    try:
        return socket.getservbyport(port,proto)
    except:
        return "UNKOWN"

def Data(ip,port,proto,os,statu):
    d = str(port) + " " + proto + " " + os + " " + statu
    if ip in data.keys():
        if d in data[ip]:
            pass
        else:
            data[ip].append(d)
            count[ip]+=1
    else:
        data[ip]=[d]
        count[ip]=1

def padding(ip,lenght):
    l=len(ip)
    if (lenght-l)%2 == 0:
        s=(lenght-l)/2
        newip=" "*s+ip+" "*s
    else:
        s = (lenght - l) / 2
        newip = " " * (s+1) + ip + " " * s
    return newip

def tableHeader():
    print("#"*88)
    print("#" + " " * 20 + "#" + " " *9 +"#"+" "*5+"#"+" "*9+"#"+" "*19+"#"+" "*19+"#")
    print("#" + " " * 9 + "IP" +" " * 9+ "#" + " " * 3+"PORT"+" "*2 + "#" + "PROTO"  + "#" + " " * 3 +"OS"+ " " * 4 + "#"+" "*6+"SERVICE"+" "*6+"#"+" "*6+"STATUS"+" "*7+"#")
    print("#" + " " * 20 + "#" + " " * 9 + "#" + " " * 5 + "#" + " " * 9 + "#"+" "*19+"#"+" "*19+"#")
    print("#"*88)

def printtable():
    for key in fdata:
        i=0
        while i<len(data[key]):
            ip=padding(key,20)
            da= data[key][i].split(" ")
            port = padding(da[0],9)
            proto = padding(da[1],5)
            os = padding(da[2],9)
            statu = padding(da[3],19)
            #print(int(da[0]),da[1])
            serv = appproto(int(da[0]),da[1])
            #print(serv)
            serv = padding(serv, 19)

            print("#"+ip+"#"+port+"#"+proto+"#"+os+"#"+serv+"#"+statu+"#")
            i+=1
        print("#" * 88)


def TCPSYN():
    key=keys[i].split()
    key1=key[0]+" "+key[3]+" > "+key[1]
    for ACKpaket in sessions[key1]:
        try:
            if ACKpaket[TCP].ack == packet[TCP].seq+1:
                if ACKpaket[TCP].flags=="SA":
                    os = ttlFingerprint(packet["IP"].ttl)
                    os1 = ttlFingerprint(ACKpaket["IP"].ttl)
                    Data(ACKpaket["IP"].src, ACKpaket["TCP"].sport, "TCP", os,"open")
                    Data(ACKpaket["IP"].dst, ACKpaket["TCP"].dport, "TCP", os1,"open")
                    #print("TCPSYN")
                    #print(ACKpaket["IP"].src,"  ", ACKpaket["TCP"].sport, " TCP ", os,"    ",ACKpaket[TCP].flags)
                    #print(ACKpaket["IP"].dst,"  ", ACKpaket["TCP"].dport, "  TCP  ", os1," ",packet[TCP].flags)
                    keyCheek[key1]=1
                    return 1
                else:
                    return 1
        except:
            pass

def ACK():
    key = keys[i].split()
    key1 = key[0] + " " + key[3] + " > " + key[1]
    for ACKpaket in sessions[key1]:
        try:
            if ACKpaket[TCP].seq == packet[TCP].ack:
                x=ACKpaket[TCP].flags
                x = bin(int(x))
                x = x[2:len(x)]
                x = x[::-1]
                if x[2]=='1':
                    return 1
                else:
                    os = ttlFingerprint(packet["IP"].ttl)
                    os1 = ttlFingerprint(ACKpaket["IP"].ttl)
                    Data(ACKpaket["IP"].src, ACKpaket["TCP"].sport, "TCP", os,"open")
                    Data(ACKpaket["IP"].dst, ACKpaket["TCP"].dport, "TCP", os1,"open")
                    #print(ACKpaket["IP"].src, "  ", ACKpaket["TCP"].sport, " TCP ", os,"    ",ACKpaket[TCP].flags)
                    #print(ACKpaket["IP"].dst, "  ", ACKpaket["TCP"].dport, "  TCP  ", os1," ",packet[TCP].flags)
                    keyCheek[key1] = 1
                    return 1
        except:
            pass

def UDP(i,packet):
    key=keys[i].split()
    key1="ICMP "+key[3].split(":")[0]+" > "+key[1].split(":")[0]+" type=3 code=3 id=None"
    test=0
    try:
        c=0
        while c<len(sessions[key1]):
            if packet["UDP"].chksum == sessions[key1][c]["UDPerror"].chksum:
                test=1
                #print(packet["UDP"].sport,"     ",packet["UDP"].dport)
            c+=1
    except:
        pass
    if test==1:
        #print(packet["UDP"].sport, "     ", packet["UDP"].dport)
        return 1
    else:
        key = keys[i].split()
        key1="UDP "+key[3]+" > "+key[1]
        if key1 in keys:
            os = ttlFingerprint(packet["IP"].ttl)
            os1 = ttlFingerprint(sessions[key1][0]["IP"].ttl)
            #print(packet["IP"].src, "    ", packet["UDP"].sport, "   UDP     ", os, "  open")
            #print(packet["IP"].dst, "    ", packet["UDP"].dport, "  UDP   ", os1, "   open")
            Data(packet["IP"].src, packet["UDP"].sport, "UDP", os,"open")
            Data(packet["IP"].dst, packet["UDP"].dport, "UDP", os1,"open")
        else:
            os = ttlFingerprint(packet["IP"].ttl)
            os1 = ttlFingerprint(100)
            #print(packet["IP"].src, "    ", packet["UDP"].sport, "   UDP     ", os, "open|filtered")
            #print(packet["IP"].dst, "    ", packet["UDP"].dport, "  UDP   ", os1, "open|filtered")
            Data(packet["IP"].src, packet["UDP"].sport, "UDP", os, "open|filtered")
            Data(packet["IP"].dst, packet["UDP"].dport, "UDP", os1, "open|filtered")
        return 1


data={}
count={}
packets = rdpcap("2018-CTF-from-malware-traffic-analysis.net-1-of-2.pcap")
sessions = packets.sessions()
keys=sessions.keys()
keyCheek={}
i=0
while i<len(keys):
    cheek = 0
    try:
        if keyCheek[keys[i]]!=1:
            pass
            '''
            for packet in sessions[keys[i]]:
                try:
                    if packet["IP"].proto == 6:
                        x = packet[TCP].flags
                        x = bin(int(x))
                        x = x[2:len(x)]
                        x = x[::-1]
                        if packet["TCP"].flags == "S":
                            cheek = TCPSYN()
                            if cheek == 1:
                                break;
                        elif x[4]=='1':
                            cheek = ACK()
                            if cheek == 1:
                                break;
                    elif packet["IP"].proto == 17:
                        cheek=UDP()
                        if cheek == 1:
                            break
                except:
                    pass
            '''
    except:
        for packet in sessions[keys[i]]:
            try:
                if packet["IP"].proto == 6:
                    x = packet[TCP].flags
                    x = bin(int(x))
                    x = x[2:len(x)]
                    x = x[::-1]
                    if packet["TCP"].flags == "S":
                        cheek = TCPSYN()
                        if cheek == 1:
                            break;
                    elif x[4]=='1':
                        pass
                        cheek = ACK()
                        if cheek == 1:
                            break;
                elif packet["IP"].proto == 17:
                    cheek = UDP(i,packet)
                    if cheek == 1:
                        break
            except:
                pass
    i+=1
'''
for key in data.keys():
    count[key]=len(data[key])
'''
fdata=[]
for key, value in sorted(count.iteritems(), key=lambda (k,v): (v,k)):
    fdata.insert(0,key)

tableHeader()
printtable()
