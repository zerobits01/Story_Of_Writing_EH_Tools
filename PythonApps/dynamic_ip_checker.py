'''
    author : zerobits01
    created: 28-Jan-2021
    purpose: sniffing LAN packets and checking ip duplicate and dyanmic IPs
'''

import re
import pyshark
import argparse
import os
from colorama import init, Fore
import subprocess
from netaddr import IPNetwork

init()


GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

parser = argparse.ArgumentParser()
parser.add_argument('--iface', help='iface that you wanna sniff it', required=True)
args = parser.parse_args()

class Validator(object):

    @staticmethod
    def validateIFace(iface):
        """checks if input interface is existing or not
        """
        command = ["ip", "addr", "show", iface]
        try:
            grepOut = subprocess.check_output(' '.join(command), shell=True)
            out_string = grepOut.decode()
            # sample inet 192.168.1.158
            get_ip_regex = re.compile(r"inet (?P<ip_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
            return get_ip_regex.search(out_string).group("ip_addr")                    
        except subprocess.CalledProcessError as grepexc:
            print("[!] entered interface doesn't exist")
            return False
    
    
    @staticmethod
    def validIPAddress(IP):
        """
        :type IP: str
        :rtype: str
        """
        ip_list = []
        for ip in IPNetwork(IP):
            ip_list.append(str(ip))
            
        return ip_list


# cap.apply_on_packets(returnSystemMac, timeout=3)    

mac_addr  = re.compile(r"Client MAC address: (?P<mac_addr>\S+)")
host_name = re.compile(r"Host Name: (?P<host_name>\S+)")
ip_addr   = re.compile(r"Requested IP Address: (?P<ip_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

def doArping(ip):
    try:
        subprocess.check_output(f"sudo arping -c 1 {ip}")    
    except Exception:
        pass                

def check_dhcp(cap):
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

def check_duplicate(cap):
    for pkt in cap:
        print(pkt)


if __name__ == "__main__":
    dhcp_cap = pyshark.LiveCapture(interface=args.iface, bpf_filter="port 67 and 68")
    check_dhcp(dhcp_cap)
    arp_cap = pyshark.LiveCapture(interface=args.iface)
    check_duplicate(arp_cap)
    dst = Validator.validIPAddress(IP=args.range)
    for ip in dst:
        if ip.__contains__(".0") or ip.__contains__(".255"):
            continue
        doArping(ip)


# adding monitor mode
'''
iw dev wlo1 interface add mon0 type monitor
Alternatively, if you can't seem to create a monitor-mode vif and you're sure the card supports the mode, try setting the existing vif to monitor mode:

ip link set down wlo1
iw dev wlo1 set monitor none
ip link set down wlo1
'''
