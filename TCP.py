'''
 0                   1                   2                   3  
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |        Destination Port       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Acknowledgment Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Offset|  Res. |     Flags     |             Window            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Checksum           |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

For more specification about Transmission control protocol see : https://tools.ietf.org/html/rfc793
'''
import random
from LIB import *
import socket

__name__ = 'TCP'
__version__ = '0.1'
__date__ = ' Mars 2018'
__author__ = 'Oussama boudar'
__email__ = 'oussama.boudar@yellowlightit.com'
__site__ = 'www.yellowlightit.com'


PackFormat= '!HHLLBBH'
PackFormatPseudoheader="!4s4sBBH"

class TCP:
	def __init__(self, ip_src,port_src,ip_dst,port_dst,payload):
		
		#the source and destination IP dont figure in the TCP sergment, but am keeping them here to use them to create the pseudo header. 	
		self.ip_src = ip_src
		self.ip_dst = ip_dst
		#The source port number
		self.port_src = port_src
		#The destination port number
		self.port_dst = port_dst
		#The sequence number of the first data octet in this segment (except when SYN is present). If SYN is present the sequence number is the initial sequence number (ISN) and the first data octet is ISN+1.
		self.sequence_number = random.randint(0,1000)
		#Acknowledgment Number 
		#If the ACK control bit is set this field contains the value of the next sequence number the sender of the segment is expecting to receive.  Once a connection is established this is always sent
		self.acknowledgment_number = 0
		#Data Offset
		# The number of 32 bit words in the TCP Header 
		# indicates where the data begins
		self.offset = 5
		#Reserved for future use.  Must be zero.
		self.reserved = 0
		#6 bits (from left to right):
		#URG:  Urgent Pointer field significant
		self.urg = 0	
		#ACK:  Acknowledgment field significant
		self.ack = 0
		#PSH:  Push Function
		self.psh = 0
		#RST:  Reset the connection
		self.rst =0
		#SYN:  Synchronize sequence numbers
		self.syn = 0
    		#FIN:  No more data from sender	
		self.fin = 0
		#Window : The number of data octets beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept.
		self.window = 29200
		self.checksum = 0
		#Urgent Pointer: 
		#communicates the current value of the urgent pointer as a positive offset from the sequence number in this segment.  The urgent pointer points to the sequence number of the octet following the urgent data.  This field is only be interpreted in segments with the URG control bit set.
		self.urgent_pointer = 0 
		#Options may occupy space at the end of the TCP header and are a  multiple of 8 bits in length.  All options are included in the checksum.  An option may begin on any octet boundary. 
		#option3 = hex(int(str((time.time())//1).split(".")[0]))
		#self.options = [0x020405b4,0x0402,0x01,0x03030700,0x00]
		self.options = 0
		self.payload = payload

	def Pack(self):

		tcp_header=self.create_tcp_header()
		psudo_header = self.create_pseudo_header(tcp_header)
		checksum_data = psudo_header + tcp_header + self.payload
		checksum = Compute_checksum(checksum_data)
		self.checksum = checksum
		tcp_header=self.create_tcp_header()
		return tcp_header + self.payload

	def UnPack(self,tcp_segment):
	
		tcp_header = unpack(PackFormat,tcp_segment[0:16])
		self.port_src=tcp_header[0]
		self.port_dst = tcp_header[1]
		self.sequence_number = tcp_header[2]
		self.acknowledgment_number = tcp_header[3]
		offset_reserved = tcp_header[4]
		self.offset = (offset_reserved >> 4)
		self.reserved = 0
		flags = tcp_header[5]
		self.fin = flags & 0x1
		self.syn = (flags & 0x2 ) >> 1
		self.rst = (flags & 0x4 ) >> 2
		self.psh = (flags & 0x8 ) >> 3
		self.ack = (flags & 0x10 ) >> 4
		self.urg = (flags & 0x20 ) >> 5
		self.window = tcp_header[6]
		self.checksum = unpack("H",tcp_segment[16:18])[0]
		self.urgent_pointer =  unpack("H",tcp_segment[18:20])[0]
		if self.offset > 5:
			self.options = unpack("!L",tcp_segment[20:self.offset*4])[0]
		self.payload = tcp_segment[self.offset*4:]

	def set_syn(self):

		self.syn = 1

	def set_ack(self):

                self.ack = 1

	def set_psh(self):

                self.psh = 1

	def set_rst(self):

		self.rst = 1

	def set_urg(self):

		self.urg = 1

	def set_fin(self):

		self.fin = 1
			
	def create_pseudo_header(self,tcp_header):
		tcp_segment_len = len(self.payload)+ len(tcp_header)
		reserved=0
		protocol = socket.IPPROTO_TCP
		src_ip = socket.inet_aton(self.ip_src)
		dst_ip = socket.inet_aton(self.ip_dst)
		return pack(PackFormatPseudoheader,src_ip,dst_ip,reserved,protocol,tcp_segment_len)
			
	def create_tcp_header(self):

		offset_reserved = (self.offset << 4) + self.reserved
		flags = self.fin + (self.syn << 1) +(self.rst << 2) +(self.psh << 3)+(self.ack << 4)+(self.urg << 5)
		tcp_header = pack(PackFormat,self.port_src,self.port_dst,self.sequence_number,self.acknowledgment_number,offset_reserved,flags,self.window) + pack("H",self.checksum) + pack("!H",self.urgent_pointer)
		if self.options !=0:
			tcp_header+= pack("!LHBLB",self.options[0],self.options[1],self.options[2],self.options[3],self.options[4])
		return tcp_header
