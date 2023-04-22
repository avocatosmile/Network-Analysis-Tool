from  scapy.all import rdpcap 

from scapy.layers.inet import *

#file = rdpcap('interface/scripts/example.pcapng')
corrupted_pkts =[]

def Portflooding(file):
    filepath = "media/"+ file
    ip_count= 0    
    packets = rdpcap(filepath)
    count = len(packets)
    src_ips = set()
    for packet in packets:
        protocaltype = packet.type
        if(protocaltype == 2048):
            src_ips.add(packet[IP].src)
            ip_count = len(src_ips)

        if(ip_count == 0):
         #print("Captured {} packets from {} unique IP addresses".format(count, ip_count))
         return False       
       
        if ip_count < count/10:
           # print("Possible port flooding attack detected!")
            return True
    return False
def DDosAttack(file):
        filepath = "media/"+ file
        
        packets = rdpcap(filepath)

        count = len(packets)
        src_ips = set()
        for packet in packets:
            src_ips.add(packet.src)
        ip_count = len(src_ips)

        
        packet_rate = count / 10
        ip_rate = ip_count / 10

        #print("Captured {} packets from {} unique IP addresses".format(count, ip_count))
        #print("Packet rate: {:.2f} packets/second".format(packet_rate))
        #print("IP rate: {:.2f} IPs/second".format(ip_rate))

      
      
        if packet_rate > 100 and ip_rate < 10:
          #  print("Possible DDoS attack detected!")
            return True
        return False





def portflooding(file):
    data =[] 
    #i want this to be an array of tuples each object should be like this
    #(vulnerability , packet , src mac)
    
    for pkt in range(len(file)):
     
 
        if(Portflooding(pkt)):
           data =data +[("Portflooding","Source: ",file[pkt].src,"Destination:",file[pkt].dst) ]
           return(data)
     
       
      
      
     
    if(len(data)==0):
        nodata = "No vulnerabilities are detected"
        return (nodata)
    return(data)



def DDOS(file):
    data =[] 
    #i want this to be an array of tuples each object should be like this
    #(vulnerability , packet , src mac)
    
    for pkt in range(len(file)):
     
       
        if(DDosAttack(pkt)):
            data =data +[("DDOS","Source: ",file[pkt].src,"Destination:",file[pkt].dst)]
            return(data)
     
    if(len(data)==0):
        nodata = "No vulnerabilities are detected"
        return (nodata)
    return(data)





