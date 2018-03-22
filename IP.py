'''

 0                   1                   2                   3  
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Source Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


For more informations about IP protocol see Internet protocol specifications on : https://tools.ietf.org/html/rfc791
'''
import socket
from struct import *
import random
import LIB


PackFormat = "!BBHHHBB"
IP_header_lenght = 20 #without using options
class IP:
	def __init__(self, ip_src, ip_dst, payload):
		
		#Source IP address
		self.ip_src = ip_src
		#destination IP address
		self.ip_dst = ip_dst
		# IP payload
		self.payload = payload
		#IP version, can be IPv4 or IPv6, here we use IPV4
		self.version = 4
		# Internet Header Length is the length of the internet header in 32 bit words,
		# and thus points to the beginning of the data.  Note that the minimum value for a correct header is 5.
		self.ihl = 5
		#The Type of Service provides an indication of the abstract parameters of the quality of service desired.
		self.type_of_service = 0
		#Total Length is the length of the datagram, measured in octets, including internet header and data Here am adding the len of the payload to the len of the IP header.
		self.total_length = len(self.payload) + calcsize(PackFormat+"H4s4s")
		#An identifying value assigned by the sender to aid in assembling the fragments of a datagram
		self.identification = random.randint(0,65535)
		#Flags : Various Control Flags 
		#Bit 0: reserved, must be zero
		#Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
		#Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.

		self.reserved_flag = 0
		self.DF_flag = 1
		self.MF_flag = 0
		
		#This field indicates where in the datagram this fragment belongs. 
		#The fragment offset is measured in units of 8 octets (64 bits).  The first fragment has offset zero.

		self.fragment_offset = 0
		#Time to Live indicates the maximum time the datagram is allowed to remain in the internet system.
		self.ttl = 255
		#Protocol field indicates the next level protocol used in the data portion of the internet datagram.
		self.protocol = socket.IPPROTO_TCP
		#A checksum on the header only, The checksum field is the 16 bit one's complement of the one's complement sum of all 16 bit words in the header.  For purposes of computing the checksum, the value of the checksum field is zero.
		self.header_checksum = 0
	
		#The options may appear or not in datagrams.	
	
	# this function performs conversions between Python values and C structs, its retuen a packed IP header.
	def Create_ip_header(self):
		#Convert an IPv4 address from dotted-quad string format to 32-bit packed binary format
		ip_src =  socket.inet_aton(self.ip_src)
		ip_dst = socket.inet_aton(self.ip_dst)
		version_ihl = (self.version << 4) + self.ihl 
		flags_fragment_offset = (self.reserved_flag << 15) + (self.DF_flag << 14) + (self.MF_flag << 13) + self.fragment_offset


		return pack(PackFormat,version_ihl, self.type_of_service,self.total_length,self.identification,flags_fragment_offset,self.ttl,self.protocol)+pack("H",self.header_checksum)+pack("!4s4s",ip_src,ip_dst)

	def Pack(self):
		ip_header = self.Create_ip_header()
		checksum = LIB.Compute_checksum(ip_header)
		self.header_checksum = checksum
		
		ip_header = self.Create_ip_header()
		return ip_header + self.payload
	
		
	def UnPack(self,ip_datagram):
		
		ip_header = unpack(PackFormat+"H4s4s", ip_datagram[0:IP_header_lenght])
		version_ihl = ip_header[0]
		self.ihl = version_ihl & 0xF
		self.version = version_ihl >> 4
		self.type_of_service = ip_header[1]
		self.total_length = ip_header[2]
		self.identification = ip_header[3]
		flags_fragment_offset = ip_header[4]
		self.fragment_offset = flags_fragment_offset & 0x1FFF
		self.reserved_flag = (flags_fragment_offset >> 13 ) & 0x4
		self.DF_flag = (flags_fragment_offset >> 14 ) & 0x2
		self.MF_flag = (flags_fragment_offset >> 15 ) & 0x1
		self.ttl = ip_header[5]
		self.protocol = ip_header[6]
		self.header_checksum = ip_header[7]
		self.ip_src = socket.inet_ntoa(ip_header[8])
		self.ip_dst = socket.inet_ntoa(ip_header[9])

		data_len = self.total_length - self.ihl * 4
		self.payload = ip_datagram[self.ihl * 4: self.ihl * 4 + data_len] 


		
		
		
		
	

		

	
		
		

