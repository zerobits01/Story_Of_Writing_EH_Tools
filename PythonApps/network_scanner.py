'''
    author : zerobits01
    created: 24-Jan-2020
    purpose: scanning the network and finds connected devices
                their IP and mac-address
'''

# we can use python nmap module(lib) too but am trying to
# implement my own net-scanner

# TODO : implementing subnet and pinging other ips

import scapy.all as scapy
import argparse

parser = argparse.ArgumentParser(description='''
    author : zerobits01
    email  : zerobits01@yahoo.com
    team   : Paradox-Squad
    description : use this app to find out all other
                    connected devices to a network 
''', formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-r','--range',help='pass the ip or ip range',
                    required=True, type=str)

args = parser.parse_args()

def net_scan_auto(ip):
    # using scapy.arping we gonna use arp protocol to find out macs
    scapy.arping(ip)

def net_scan_manually(ip):
    # scapy has implemented ls method for all objects that shows all attrbs
    # packets has two methods show the res : show, summary
    '''
        for being sure that requests are sended to all nodes
        we set the destination mac to broadcast then all nodes will
        recieve the request and send back a response 
    '''
    arp_packet = scapy.ARP(pdst=ip) # this sends to IP[s]
    # packet is in tcp/ip layer we need the physical layer an Ethernet-Frame
    # then we append the arp packet to the ethernet-frame
    ethernet_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.ls(scapy.Ether())
    arp_req = ethernet_frame/arp_packet # arp request frame
    '''
        scapy has two methods for sending request :
            sr : send and receive
            srp : send and receive (ether customized)
                srp returns two values (answered, unanswered)
    '''
    nodes, _ = scapy.srp(arp_req, timeout=1, verbose=False) # _ is unanswered packets
    return [{'ip' : node[1].pdst,'mac' : node[1].hwdst} for node in nodes]

def print_result(nodes):
    for node in nodes :
        print(node['ip'], node['mac'], sep=' => ')

# net_scan_auto('192.168.1.1/24')
if __name__ == '__main__':
    try :
        print('[!] please wait.')
        nodes = net_scan_manually(args.range)
        print_result(nodes)
        print('[+] done as well.')
    except Exception :
        print('[-] sorry something unexpected happened.')