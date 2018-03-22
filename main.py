import TCP,IP,Ethernet,ARP
from LIB import *
import threading
import time

interface = "enp3s0"
ip_src = spa = "192.168.0.128"
ip_dst = tpa = "192.168.0.138"
THA = SHA = mac_src = "48:4d:7e:cd:28:d0"
mac_dst = "f8:db:88:fb:ed:ea"
port_src= 36132
port_dst = 4445


arp = create_arp_packet(spa,tpa,SHA,THA,mac_src)

arp_reponse_thread = threading.Thread(target=sendarp, args=(interface,arp,))
arp_reponse_thread.start()

#time.sleep(10)

connect_tcp (interface,ip_src,port_src,ip_dst,port_dst,mac_src,mac_dst)



