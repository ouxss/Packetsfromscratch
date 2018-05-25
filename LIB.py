from struct import *
import socket
import TCP,IP,Ethernet,ARP
import random
import time

__name__ = 'LIB'
__version__ = '0.1'
__date__ = ' Mars 2018'
__author__ = 'Oussama boudar'
__email__ = 'oussama.boudar@yellowlightit.com'
__site__ = 'www.yellowlightit.com'

seq_num = 0

def sendarp(interface,arp):
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        raw_socket.bind((interface, socket.SOCK_RAW))
        while True:
                raw_socket.send(arp)

def Compute_checksum(header):

	if len(header) % 2 == 1:
		header += pack('B',0)	
	checksum = 0
	for i in range (0,len(header),2):
		w = ord(header[i])+ (ord(header[i+1])  << 8 )
		checksum += w
	checksum = (checksum  >> 16) + (checksum & 0xffff)
 	checksum += (checksum >> 16)
	checksum =  ~checksum & 0xffff
	return checksum

def Convert_mac_address(mac):

    hexs = map(lambda x: int(x, 16), mac.split(':'))
    return pack('!6B', hexs[0], hexs[1], hexs[2], hexs[3], hexs[4],
                       hexs[5])

def Convert_mac_to_str(mac):

	address = unpack("!6B",mac)
	ddr = map(lambda x: hex(x).split('0x')[1] , address)			
	mac = ""
	for el in ddr:
		if mac == "":
			mac=el
		else:	
			mac += ":" + str(el)
	return mac

def Pack_tcp_packet(ip_src,port_src,ip_dst,port_dst,mac_src,mac_dst,flags,**kwargs):
	
	tcp = TCP.TCP(ip_src,port_src,ip_dst,port_dst,"")
	if "urg" in flags:
		tcp.set_urg()
	if "ack" in flags:
		tcp.set_ack()
	if "psh" in flags:
		tcp.set_psh()
	if "rst" in flags:
		tcp.set_rst()
	if "syn" in flags:
		tcp.set_syn()
	if "fin" in flags:
		tcp.set_fin()
	if "acknowledgment_number" in kwargs:
		tcp.acknowledgment_number = kwargs["acknowledgment_number"] 
	if "sequence_number" in kwargs:
		tcp.sequence_number = kwargs["sequence_number"]
	if "payload" in kwargs:
		tcp.payload= kwargs["payload"]
	tcp_header = tcp.Pack()
	ip = IP.IP(ip_src,ip_dst,tcp_header)
	ip_header = ip.Pack()
	mac_src = Convert_mac_address(mac_src)
	mac_dst = Convert_mac_address(mac_dst)
	ethernet = Ethernet.Ethernet(mac_src,mac_dst,0x0800,ip_header)
	packet = ethernet.Pack()
	return packet,tcp.sequence_number

def UnPack_tcp_packet(packet):
		
	tcp = None
	try:
		ethernet = Ethernet.Ethernet("","","","")
		ethernet_payload = ethernet.UnPack(packet)
	        ip = IP.IP("","","")
	        ip.UnPack(ethernet.Ethernet_payload)
        	tcp = TCP.TCP("","","","","")
	        tcp.UnPack(ip.payload)
				
	except Exception,e:
		return None

	return tcp


def create_arp_packet(spa,tpa,SHA,THA,mac_src):

	SHA = Convert_mac_address(SHA)
	THA = SHA = Convert_mac_address(THA)
	arp = ARP.ARP(SHA,spa,THA,tpa)
	arp_header = arp.Pack()
	mac_dst = Convert_mac_address("ff:ff:ff:ff:ff:ff")
	ethernet= Ethernet.Ethernet(mac_src,mac_dst,0x0806,arp_header)
	packet = ethernet.Pack()
	return packet
	
def connect_tcp(interface,ip_src,port_src,ip_dst,port_dst,mac_src,mac_dst):

	raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
	raw_socket.bind((interface, socket.SOCK_RAW))
	seq_num = 0
	port_src = random.randint(5000,10000)
	print "[+] start TCP three-way handshake"
	#create a tcp packet
	flags = "syn"
	tcp_syn,seq_num = Pack_tcp_packet(ip_src,port_src,ip_dst,port_dst,mac_src,mac_dst,flags)
	raw_socket.send(tcp_syn)
	print " |		[->] Sending tcp syn packet"
	kwargs = {"ack":1,"syn":1}
	received_tcp = receive_tcp(interface,port_src,port_dst,**kwargs)
	if received_tcp:
		print " |		[<-] syn_ack packet received"	
		print " |		[->] Sending tcp ack packet"
		flags = "ack"
		seq_num += 1
		kwargs = {"sequence_number":seq_num,"acknowledgment_number":received_tcp.sequence_number +1}
		tcp_ack,seq_num2 = Pack_tcp_packet(ip_src,port_src,ip_dst,port_dst,mac_src,mac_dst,flags,**kwargs)
		raw_socket.send(tcp_ack)
		print "[+] TCP three-way handshake completed"
		received_tcp,seq_number =Receive_and_send_ack(interface,seq_num,port_src,port_dst,ip_src,ip_dst,mac_src,mac_dst,raw_socket)
                received_tcp,seq_number =Receive_and_send_ack(interface,seq_number,port_src,port_dst,ip_src,ip_dst,mac_src,mac_dst,raw_socket)
		cmd="dir\n"
		received_tcp,seq_number = send_cmd_dir(interface,seq_number,port_src,port_dst,ip_src,ip_dst,mac_src,mac_dst,raw_socket,received_tcp,cmd)

def send_cmd_dir(interface,seq_num,port_src,port_dst,ip_src,ip_dst,mac_src,mac_dst,raw_socket,received_tcp,cmd):
			
		seq_number = seq_num			
		flags = "ack,psh"
                kwargs = {"sequence_number":seq_number,"acknowledgment_number":received_tcp.sequence_number + len(received_tcp.payload),"payload":cmd}
                tcp_psh,seq_num = Pack_tcp_packet(ip_src,port_src,ip_dst,port_dst,mac_src,mac_dst,flags,**kwargs)
                raw_socket.send(tcp_psh)
		received_tcp,seq_number =Receive_and_send_ack(interface,seq_num,port_src,port_dst,ip_src,ip_dst,mac_src,mac_dst,raw_socket)
		received_tcp,seq_number =Receive_and_send_ack(interface,seq_num,port_src,port_dst,ip_src,ip_dst,mac_src,mac_dst,raw_socket)
		return received_tcp,seq_number

def Receive_and_send_ack(interface,seq_num,port_src,port_dst,ip_src,ip_dst,mac_src,mac_dst,raw_socket):
        kwargs = {"ack":1,"psh":1}
        received_tcp = receive_tcp(interface,port_src,port_dst,**kwargs)
        if received_tcp:
                        print received_tcp.payload
                        seq_number = seq_num 
                        flags = "ack"
                        kwargs = {"sequence_number":seq_number,"acknowledgment_number":received_tcp.sequence_number  + len(received_tcp.payload)}
                        tcp_ack,seq_num = Pack_tcp_packet(ip_src,port_src,ip_dst,port_dst,mac_src,mac_dst,flags,**kwargs)
                        raw_socket.send(tcp_ack)
                        return received_tcp,seq_number
        return False
 
def receive_tcp(interface,port_src,port_dst,**kwargs):
	buffer_size = 65536
	raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        raw_socket.bind((interface, socket.SOCK_RAW))
	while True:
		packet = raw_socket.recvfrom(buffer_size)[0]
		tcp = UnPack_tcp_packet(packet)
		if tcp == None:
			continue	
		try:
			if tcp.port_src == port_dst and tcp.port_dst == port_src:
				if "urg" in kwargs and kwargs["urg"]!=tcp.urg:
					continue
				if "ack" in kwargs and kwargs["ack"]!=tcp.ack:
					continue
				if "psh" in kwargs and kwargs["psh"]!=tcp.psh:
                        	        continue
				if "rst" in kwargs and kwargs["rst"]!=tcp.rst:
        	                        continue
				if "syn" in kwargs and kwargs["syn"]!=tcp.syn:
                        	        continue

				if "fin" in kwargs and kwargs["fin"]!=tcp.fin:
        	                        continue				
				return tcp
		except:
			pass
