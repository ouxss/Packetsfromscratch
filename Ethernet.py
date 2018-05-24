'''
 0                   1                   2                   3                   4              
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                      Destination Address                                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                         Source Address                                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           EtherType           |                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                               +
|                                                                                               |
+                                            Payload                                            +
|                                                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


'''

from struct import *
from LIB import *

__name__ = 'Ethernet'
__version__ = '0.1'
__date__ = ' Mars 2018'
__author__ = 'Oussama boudar'
__email__ = 'oussama.boudar@yellowlightit.com'
__site__ = 'www.yellowlightit.com'



ETHERNET_HEADER_LENGH = 14
PackFormat = "!6s6sH"


class Ethernet:
	def __init__(self, mac_src,mac_dst,Ethernet_type , Ethernet_payload):
		
		#MAC source address
		self.mac_src = mac_src
		#MAC destination address
		self.mac_dst = mac_dst
		#Type of Ethernet frame
		self.Ethernet_type = Ethernet_type
		#Ethernet payload
		self.Ethernet_payload = Ethernet_payload

	#This function convert the ethernet object to byte.
	def Pack(self):
	
		Ethernet_header = pack(PackFormat,self.mac_dst,self.mac_src,self.Ethernet_type)

		Ethernet_frame = Ethernet_header + self.Ethernet_payload 
		
		return Ethernet_frame

	def UnPack(self,Ethernet_frame):

		Ethernet_header = unpack(PackFormat,Ethernet_frame[0:ETHERNET_HEADER_LENGH])
		self.mac_dst = Ethernet_header[0]
		
		self.mac_src = Ethernet_header[1]
		self.Ethernet_type =  Ethernet_header[2]
		self.Ethernet_payload = Ethernet_frame[ETHERNET_HEADER_LENGH:]

		
		
	
