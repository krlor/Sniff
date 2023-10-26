"""
观察到目前所截获的数据包都是以太网II型的帧，因此以这个方式来处理。
6字节：目的MAC。6字节：源MAC.2字节：0x0800 IPV4,0x0806 ARP,0x22F0 AVTP,0x8100 VLAN TAG(TPID),0x86DD IPV6,0x8870 Jumbo Frame,0x88F7 PTP/gPTP。
以上是EthernetII型帧结构，接下来是IP数据包结构。
"""
import os
import io
import sys
pck_list=[]
file = open("C:/Users/M/Desktop/test.txt", "r")  # 将所有数据以十六进制读入pck_list列表，并且将后面的‘\n’和前面的'0x'去掉。
fr = file.readlines()
pck_list = []
emptyfilecheck = os.path.getsize("C:/Users/M/Desktop/test.txt")
if emptyfilecheck != 0:
    for line in fr:
        pck_list.append(line.strip())

    for i in range(len(pck_list)):
        pck_list[i] = pck_list[i][2:]
def packet_handlers(list):
        print("src_MAC:",list[0:2],":",list[2:4],":",list[4:6],":",list[6:8],":",list[8:10],":",list[10:12])  #MAC地址
        print("dst_MAC:",list[12:14],":",list[14:16],":",list[16:18],":",list[18:20],":",list[20:22],":",list[22:24])

        count=list[24:28] #Types,类型
        if int(count,16)==int('0800',16):
            print("Types:IPV4")
        elif int(count,16)==int('0806',16):
            print("Types:ARP")
        elif int(count, 16) == int('86DD', 16):
            print("Types:IPV6")
        else:
            print('Unknown Types')

        if  int(count,16)==int('0800',16): #如果是IPV4格式：
            print("header length:",4*int(list[29],16))
            print("Total lenth:",int(list[32:36],16))
            print("identification:",list[36:40])
            print("TTL:",int(list[44:46],16))
            if int(list[46:48],16)==1:
                print("Protocols:ICMP")
            elif int(list[46:48],16)==2:
                print("Protocols:IGMP")
            elif int(list[46:48], 16) == 6:
                print("Protocols:TCP")
            elif int(list[46:48],16)==8:
                print("Protocols:EGP")
            elif int(list[46:48],16)==9:
                print("Protocols:IGP")
            elif int(list[46:48],16)==17:
                print("Protocols:UDP")
            elif int(list[46:48],16)==41:
                print("Protocols:IPV6")
            elif int(list[46:48],16)==50:
                print("Protocols:ESP")
            elif int(list[46:48], 16) == 89:
                print("Protocols:OSPF")
            print("src_IP:",int(list[50:52],16),".",int(list[52:54],16),".",int(list[54:56],16),".",int(list[56:58],16))
            print("dst_IP:",int(list[58:60],16),".",int(list[62:64],16),".",int(list[64:66],16),".",int(list[66:68],16))
            if int(list[46:48],16)==6:  #TCP，继续解析端口号。
                print("src_port:",int(list[68:72],16))
                print("dst_port:",int(list[72:76],16))
        if int(count,16)==int('86DD',16): #如果是IPV6
            print("Traffic class:",list[29:31])
            print("Flow Label:",list[31:36])
            print("Payload length:",int(list[36:40],16))
            if int(list[40:42],16)==58:
                print("Next header:58(ICMPV6)")
            else:
                print("Next header:",list[40:42])
            print("Hop Limit:",int(list[42:44],16))
            print("src_IP(V6):",list[44:48],":",list[48:52],":",list[52:56],":",list[56:60],":",list[60:64],":",list[64:68],":",list[68:72],":",list[72:76])
            print("dst_IP(V6):",list[76:80],":",list[80:84],":",list[84:88],":",list[88:92],":",list[92:96],":",list[96:100],":",list[100:104],":",list[104:108])

analsistic=[]
for i in range(len(pck_list)):
    old=sys.stdout
    new=io.StringIO()
    sys.stdout=new
    packet_handlers(pck_list[i])
    sys.stdout=old
    # print("test:",new.getvalue())
    analsistic.append(new.getvalue())

print(analsistic)