'''
    author  : zerobits01
    created : 27-Jan-2021
    modified:
    purpose : checking the LAN for duplicate ip address and reporting mac
'''

import argparse
import scapy.all as scapy
import subprocess
import re
import time
import sys


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

def getMac(ip):
    # getting mac-addr of an entered ip
    try :
        arp_packet = scapy.ARP(pdst=ip)  # this sends to IP[s]
        return scapy.sr(arp_packet, timeout=2, verbose=False)[0][0][1].hwsrc
    except Exception :
        print('[-] unexpected error occurred during getting mac!?!')
        exit(1)

# TODO: check interface existance


# TODO: check range format


# TODO: creating LAN ip address


# TODO: checking mac addresses



if __name__ == "__main__":
    try:
        print(args.interface)
        print(args.range)
    except Exception as e:
        print(sys.exc_info()[-1].tb_lineno, e)