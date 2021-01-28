'''
    author  : zerobits01
    created : 27-Jan-2021
    modified:
    purpose : checking the LAN for duplicate ip address and reporting mac
'''

import argparse
import scapy
import scapy.all as net_helper
import subprocess
import re
import time
import sys
from netaddr import IPNetwork
import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor


def force_async(fn):
    '''
        turns a sync function to async function using threads
    '''
    pool = ThreadPoolExecutor()

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        future = pool.submit(fn, *args, **kwargs)
        return asyncio.wrap_future(future)  # make it awaitable

    return wrapper



parser = argparse.ArgumentParser(description='''
    author : zerobits01
    team   : 4squad-magni5
    gmail  : zerobist01@gmail.com
    description : run the script with interface name as arg
''',formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-i','--interface',type=str,
                    help='NIC that you want to choose',required=True)

parser.add_argument('-r','--range',type=str,
                    help='ip address range to check',required=True)

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


@force_async
def getMac(src, ip):
    # getting mac-addr of an entered ip
    try :
        print(f"checking\t{ip}")
        # subprocess.check_output(f"sudo arping -c 1 {ip}", shell=True)
        arp_packet = net_helper.ARP(op=1, psrc=src, pdst=ip)
        # ans, unans = net_helper.sr(arp_packet, multi=1, timeout=2)
        net_helper.send(arp_packet, verbose=False)
        packets = scapy.sendrecv.sniff(count=2, lfilter = lambda x: x.haslayer(scapy.layers.l2.ARP) and x.psrc == ip, timeout=3) 
        
        # lfilter = lambda x: x.haslayer(net_helper.ARP) 
        
        mac = []
        
        for packet in packets:
            mac.append(packet) # [0][0][1].hwsrc
        
        if len(mac) >= 2:
            print(20*"#")
            print(f"ip dup on {mac[0].psrc}")
            for m in mac:
                print(m.hwsrc)
            print(20*"#")
             
                   
        # return scapy.sr(arp_packet, timeout=2, verbose=False)[0][0][1].hwsrc
    except Exception as e:
        print(e)
        print('[-] unexpected error occurred during getting mac!?!')
        exit(1)


# results, unanswered = sr(ARP(op=ARP.who_has, psrc='192.168.1.2', pdst='192.168.1.1'))
# 1 req two replies, i have to handle this

requests = []


if __name__ == "__main__":
    try:
        src = Validator.validateIFace(iface=args.interface)
        dst = Validator.validIPAddress(IP=args.range)
        for ip in dst:
            if ip.__contains__(".0") or ip.__contains__(".255"):
                continue
            getMac(src, ip)

    except Exception as e:
        print(sys.exc_info()[-1].tb_lineno, e)
        

        
# ans, unans = net_helper.srp(net_helper.Ether(dst="ff:ff:ff:ff:ff:ff")/net_helper.ARP(pdst="192.168.1.0/24"))
# ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
