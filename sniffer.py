from prettytable import PrettyTable  #for better layout
import struct
import socket
from struct import *

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ethernet_frame_resolution(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[:14]
    
def ip_packet_resolution(ip_header):
    iph=iph = unpack('!BBHHHBBH4s4s' , ip_header)
    version_ihl = iph[0]
    version=version_ihl>>4
    version= "IPV"+str(version)
    ihl= version_ihl & 0xF
    iph_length= ihl*4
    ttl=iph[5]
    protocol=iph[6]
    if protocol==6: 
        protocol="TCP"
    elif protocol==1:
        protocol="ICMP"
    elif protocol==17:
        protocol="UDP"
    source_address=socket.inet_ntoa(iph[8]);
    destination_address=socket.inet_ntoa(iph[9]);
    return version,ttl,protocol,source_address,destination_address;

def tcp_resolution(tcp_header):
    tcph = unpack('!HHLLH' , tcp_header)
    source_port= tcph[0]
    destination_port=tcph[1]
    sequence=tcph[2]
    ack=tcph[3]
    flags=tcph[4]
    return source_port,destination_port,sequence,ack,flags;

def udp_resolution(udp_header):
    udph = unpack('!HHHH' , udp_header)
    source_port=udph[0]
    destination_port=udph[1]
    length=udph[2]
    checksum=udph[3]
    return source_port,destination_port,length,checksum;

def icmp_resolution(icmp_header):
    icmph = unpack('!BBH', icmp_header)
    icmp_type = icmph[0]
    code=icmph[1]
    checksum=icmph[2]
    return icmp_type,code,checksum;
    

def extract_Data(packet,headers):
    data_length=len(packet)-headers;
    data=packet[:headers]
    print(" Data \n")
    return data;
    
    
def main():
    print("****************************************************************************************************\n\n")
    print("\t\t\t\t\t Gaurav\n \t\t\t\t\t 18JE0311\n \t\t\t\t\t 7th Semester \n")
    print("\t\t\t\t\t PACKET SNIFFER : COMMUNICATION NETWORKS TERM PROJECT \n")
    print("****************************************************************************************************\n\n")
    # conn = socket.socket( socket.AF_PACKET socket.SOCK_RAW , socket.ntohs(0x0003))
    conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    print("Socket created")
    count =5;
    while count:
        packet= conn.recvfrom(65565)
        packet = packet[0]
        eth_length=14
        iph_length=20
        tcp_length=80
        dest_mac, src_mac, ethernet_protocol, data = ethernet_frame_resolution(packet)
        EthernetTable = PrettyTable(["Source MAC Address", "Destination MAC Address", "Network Layer Protocol"])
        EthernetTable.add_row([src_mac, dest_mac,"IPV4" if ethernet_protocol==8 else "Others"])
        print(EthernetTable)
        
        if ethernet_protocol==8:
            ip_header = packet[eth_length:20+eth_length]
            version,ttl,protocol,source_address,destination_address=ip_packet_resolution(ip_header)
            IPTable =PrettyTable(["Version", "Time To Live", "Transport Layer Protocol","Source IP","Destination IP"])
            IPTable.add_row([version,ttl,protocol,source_address,destination_address])
            print(IPTable)
            
            if protocol=="TCP":
                tcp_header=packet[eth_length+iph_length:eth_length+iph_length+14]
                source_port,destination_port,sequence,ack,flags=tcp_resolution(tcp_header)
                finish_flag=(flags & 1)>>0   #to check if ith bit is set in N : (1<<i) & n OR (n & pow(2,i))>>i
                syn_flag=(flags & 1)>>1
                reset=(flags & 4)>>2
                push_fn=(flags & 8)>>3
                ack_flag=(flags & 16)>>4
                urgent_pointer=(flags & 32)>>5
                TCPTable=PrettyTable(["Source Port", "Destination Port", "Sequence","Acknowlwdgement","flags: F|S|R|P|A|U  "])
                TCPTable.add_row([source_port,destination_port,sequence,ack,str(finish_flag)+"|"+str(syn_flag)+"|"+str(reset)+"|"+str(push_fn)+"|"+str(ack_flag)+"|"+str(urgent_pointer)])
                print(TCPTable)
                data=extract_Data(packet,eth_length+iph_length+80)
                print(data);
                
            elif protocol=="UDP":
                udp_header=packet[eth_length+iph_length:eth_length+iph_length+8]
                source_port,destination_port,length,checksum=udp_resolution(udp_header)
                UDPTable=PrettyTable(["Source Port", "Destination Port", "Length","checksum"])
                UDPTable.add_row([source_port,destination_port,length,checksum])
                print(UDPTable)
                data=extract_Data(packet,eth_length+iph_length+8)
                print(data)

                
            elif protocol=="ICMP":
                icmp_header=packet[eth_length+iph_length:eth_length+iph_length+4]
                icmp_type,code,checksum=icmp_resolution(icmp_header)
                ICMPTable=PrettyTable(["ICMP Type","Code","Checksum"])
                ICMPTable.add_row([icmp_type,code,checksum])
                print(ICMPTable)
                data=extract_Data(packet,eth_length+iph_length+4)
                print(data);
        count=count-1
main()
    
