import networkx as nx
import matplotlib.pyplot as plt
from  scapy.all import rdpcap 
from scapy.layers.inet import *
from scapy.layers.tls.all import *
from scapy.layers import inet
from scapy.layers.l2 import ARP





def makemap(name):
    filepath = "media/"+name
    print(filepath)
    file = rdpcap(filepath)
    networknode=[""]
    
    Networkmap = nx.Graph()
    for x in range(len(file)):
        
        source=file[x].src
        destination=file[x].dst
        if (x==1):
            networknode=[(source,destination)]
        else:
            networknode=networknode+[(source,destination)]

    

    
    for pos in range(len(networknode)): 
        
        edge1= networknode[pos][0]
        edge2= networknode[pos][1]
        Networkmap.add_edge(edge1, edge2)



    nx.draw_circular(Networkmap, with_labels = True, font_size=9)
    picname =  name  +".png"
   # path ="interface/static/images/networkDiagrams/"+ picname
    path ="media/"+ picname
    local ="/images/networkDiagrams/"+ picname
    plt.savefig(path,  dpi=200,bbox_inches = "tight")
    plt.clf()
    return picname

def netstat(name):
    filepath = "media/"+name
  
    file = rdpcap(filepath)
    source=[]
    destination =[]
    sourcemac= []
    destinationmac =[]
    sourcearp=[]
    destinationarp =[]
    sourcemacarp= []
    destinationmacarp =[]
  
        
    for packet in file :
        protocaltype = packet.type
        counter =1 
        if(protocaltype == 2048):
                src = packet[IP].src
                dst =packet[IP].dst
                srcmac = packet.src
                dstmac =packet.dst
                source= source +[src]
                destination= destination +[dst]
                sourcemac= sourcemac +[srcmac]
                destinationmac= destinationmac +[dstmac]
        elif(protocaltype == 2054) :
            
                srcarp = packet[ARP].psrc
                dstarp =packet[ARP].pdst
                srcmacarp = packet.src
                dstmacarp =packet.dst
                sourcearp= sourcearp +[srcarp]
                destinationarp= destinationarp +[dstarp]
                sourcemacarp= sourcemacarp +[srcmacarp]
                destinationmacarp= destinationmacarp +[dstmacarp]



    return source , destination ,sourcemac , destinationmac ,sourcearp , destinationarp ,sourcemacarp , destinationmacarp
def protocols(name):
    filepath = "media/"+name
    file = rdpcap(filepath)
    
    
    tcp_packets = [pkt for pkt in file if TCP in pkt]
    udp_packets = [pkt for pkt in file if UDP in pkt]
    icmp_packets = [pkt for pkt in file if ICMP in pkt]
    ssl_packets = [pkt for pkt in file if pkt.haslayer('TLS')]
    arp_packets = [pkt for pkt in file if ARP in pkt]

   # print(arp_packets ,tcp_packets , udp_packets ,icmp_packets,ssl_packets)
    return len(arp_packets) ,len(tcp_packets) , len(udp_packets) ,len(icmp_packets),len(ssl_packets) 


def mostactiveips(name ):
    filepath = "media/"+name
    file = rdpcap(filepath)
    values=[]
    positon =0
    mostrepeated=0
    for pos in file: 
    
        counter =0
        
        for x in file :
            if pos.src == x.src :
               
                if mostrepeated == counter or   counter >mostrepeated :
                
                    mostrepeated = counter 
                    Ipaddress = pos.src
                  
                counter = counter +1 
                
            
    return(mostrepeated , Ipaddress)
def suspicouspkt(name): 
    suspiciouspackets =[]
    filepath = "media/"+name
    file = rdpcap(filepath)
    biggest =0
    for x in file :
        c=0
        protocaltype = x.type
        if(protocaltype == 2054):
            #print("mac:",x.src ,"IP:",x[ARP].psrc)
            #print(" Destination mac:",x.dst ,"IP:",x[ARP].pdst)
            for p in file:
                if(protocaltype == 2054):
                    if x == p :
                        c = c+1
                        if (c > biggest or c == biggest):
                            biggest =c
                            
                            if biggest>30:
                                if x.src in suspiciouspackets:
                                    pass
                                else:
                                 suspiciouspackets =suspiciouspackets+[x.src]
                                 
                            
    return suspiciouspackets        
        