'''
    author : zerobits01
    created: 29-Jan-2020
    purpose: sniffing incoming and outgoing packets
        usually we use with MITM(e.g : arp_spoofer)
'''

import re
import pyshark
import argparse
import os
from colorama import init, Fore
# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

parser = argparse.ArgumentParser()
parser.add_argument('--iface', help='iface that you wanna sniff it', required=True)
args = parser.parse_args()



# cap.apply_on_packets(returnSystemMac, timeout=3)    

mac_addr  = re.compile(r"Client MAC address: (?P<mac_addr>\S+)")
host_name = re.compile(r"Host Name: (?P<host_name>\S+)")
ip_addr   = re.compile(r"Requested IP Address: (?P<ip_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

def check_dhcp():
    for pkt in cap:
        dhcp_hdr = str(pkt.dhcp)
        m1 = mac_addr.search(dhcp_hdr)
        m2 = host_name.search(dhcp_hdr)
        m3 = ip_addr.search(dhcp_hdr)
        if m1 and m2 and m3:
            mac    = m1.group("mac_addr")
            hname  = m2.group("host_name")
            ipaddr = m3.group("ip_addr")
            print(hname + ":\t" + mac + "\tgot ip:\t" + ipaddr)


def check_duplicate():
    pass


if __name__ == "__main__":
    cap = pyshark.LiveCapture(interface=args.iface, bpf_filter="port 67 and 68")
    check_dhcp()

# adding monitor mode
'''
iw dev wlo1 interface add mon0 type monitor
Alternatively, if you can't seem to create a monitor-mode vif and you're sure the card supports the mode, try setting the existing vif to monitor mode:

ip link set down wlo1
iw dev wlo1 set monitor none
ip link set down wlo1
'''