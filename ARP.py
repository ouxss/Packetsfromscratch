'''
		28-octet ARP request/reply
                  |                                        |
      /---------------------------+------------------------------\
      |                                                           |
            2   2  1 1  2       6         4           6       4
      	  +---+---+-+-+---+-----------+-------+-----------+-------+
          |   |   |H|P|   |  Sender   | Sender|  Target   |Target |
      	  |HT |PT |S|S|OP | Ethernet  |  IP   | Ethernet  |  IP   |
      	  |   |   | | |   |  Address  |Address|  Address  |Address|
      	  +---+---+-+-+---+-----------+-------+-----------+-------+

for more information about ARP see : https://en.wikipedia.org/wiki/Address_Resolution_Protocol
'''

from struct import *
import socket
PAckFormat = "!HHBBH6s4s6s4s"
class ARP():
	def __init__(self,SHA,SPA,THA,TPA):
		#This field specifies the network protocol type. Ethernet is 1.
		self.HT = 1
		#This field specifies the internetwork protocol for which the ARP request is intended. For IPv4, this has the value 0x0800
		self.PT = 0x0800
		#Length (in octets) of a hardware address. Ethernet addresses size is 6
		self.HS = 6
		#Length (in octets) of addresses used in the upper layer protocol. (The upper layer protocol specified in PTYPE.) IPv4 address size is 4.
		self.PS = 4
		#Specifies the operation that the sender is performing: 1 for request, 2 for reply.
		self.OP = 2
		#Sender hardware address (SHA)
		# In an ARP reply this field is used to indicate the address of the host that the request was looking for.
		self.SHA = SHA
		#Sender protocol address (SPA)
		#Internetwork address of the sender.
		self.SPA = SPA
		#Target hardware address (THA)
		#In an ARP reply this field is used to indicate the address of the host that originated the ARP request	
		self.THA = THA
		#Target protocol address (TPA)
		#Internetwork address of the intended receiver.
		self.TPA=TPA

	def Pack(self):
		return pack(PAckFormat,self.HT,self.PT,self.HS,self.PS,self.OP,self.SHA,socket.inet_aton(self.SPA),self.THA,socket.inet_aton(self.TPA))
	
	def UnPAck(self,packet):
		arp_header = unpack(PAckFormat,packet[:28])
		self.HT = arp_header[0]
		self.PT = arp_header[1]
		self.HS = arp_header[2]
		self.PS = arp_header[3]
		self.OP = arp_header[4]
		self.SHA = arp_header[5]
		self.SPA = socket.inet_ntoa(arp_header[6])
		self.THA = arp_header[7]
		self.TPA = socket.inet_ntoa(arp_header[8])
		

		
		
	
		



