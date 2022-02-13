###########################################Author###################################
# Author : zerobits01
# gmail  : zerobits0101@gmail.com
# github : http://github.com/zerobits01
# Purpose: implementing ping with scapy and simulating it as OS
###########################################Imports##################################

import argparse
import time
import scapy.all as scapy
import re
import ipaddress
from colorama import Fore
import multiprocessing as mp
from socket import * # it has also gethostbyname
from icmplib import ping, multiping
import nmap
# import asyncio
# import functools
# from concurrent.futures import ThreadPoolExecutor

###########################################Arguments################################

parser = argparse.ArgumentParser(
    description="""
        this is for pinging a destination
    """,
    formatter_class=argparse.RawTextHelpFormatter
)

parser.add_argument('string', metavar='S', type=str, # nargs='+',
                    help='a string formatted in IP or FQDN format to do ping')

parser.add_argument("-t", dest="till_break", action="store_const", const=True, default=False,
                    help="use this switch to do ping till you break")

group = parser.add_mutually_exclusive_group(required=False)

group.add_argument("-r", '--scan-range', action="store_const", const=True, default=False,
                    help="use this switch when you wanna scan a range of IP for online nodes")
group.add_argument("-p", '--ping', action="store_const", const=True, default=False,
                    help="use this switch when you wanna scan a range of IP for online nodes")
group.add_argument("-s", '--scan-port', action="store_const", const=True, default=False,
                    help="use this switch when you wanna scan a range of ports on a specific IP")
parser.add_argument("-start", type=int, default=1, 
                    help="use this switch when you wanna scan a range of ports on a specific IP")
parser.add_argument("-end", type=int, default=65535, 
                    help="use this switch when you wanna scan a range of ports on a specific IP")

###########################################Variables################################

TIMEOUT = 3
scapy.conf.verb = 0

###########################################Classes##################################

class IPChecker(object):

    @staticmethod
    def is_ipv4_range_valid(range):
        groups = re.search(
            r"(?P<o1>\d{1,3})\.(?P<o2>\d{1,3})\.(?P<o3>\d{1,3})\.(?P<o4>\d{1,3})/(?P<mask>\d{1,3})",
            range
        )

        if groups is not None:
            if 0 <= int(groups.group('o1')) < 255:
                if 0 <= int(groups.group('o2')) < 255:
                    if 0 <= int(groups.group('o3')) < 255:
                        if 0 <= int(groups.group('o4')) < 255:
                            if 0 <= int(groups.group('mask')) <= 32:
                                return True
        groups_zero = re.search(
            r"(?P<o1>\d{1,3})\.(?P<o2>\d{1,3})\.(?P<o3>\d{1,3})\.(?P<o4>\d{1,3})",
            range
        )
        if groups_zero is not None:
            if 0 < int(groups_zero.group('o1')) < 255:
                if 0 < int(groups_zero.group('o2')) < 255:
                    if 0 < int(groups_zero.group('o3')) < 255:
                        if 0 < int(groups_zero.group('o4')) < 255:
                            return True
        return False

###########################################Functions################################

# def force_async(fn):
#     '''
#         turns a sync function to async function using threads
#     '''
#     pool = ThreadPoolExecutor()

#     @functools.wraps(fn)
#     def wrapper(*args, **kwargs):
#         future = pool.submit(fn, *args, **kwargs)
#         return asyncio.wrap_future(future)  # make it awaitable

#     return wrapper

# @force_async
def do_ping(dst: str, net_scan=True) -> bool:
    '''check if its FQDN then resolv if its IP then do ping one time
    '''
    global online_hosts
    # packet = scapy.IP(dst="192.168.0." + str(dst), ttl=20)/scapy.ICMP()
    t1 = time.perf_counter()
    packet = scapy.IP(dst=dst)/scapy.ICMP()
    # answered, unanswered = scapy.sr(packet, timeout=TIMEOUT)
    scapy.sr1(packet, timeout=TIMEOUT)
    reply = scapy.sr1(packet, timeout=TIMEOUT)
    # print(answered, unanswered)
    if reply:
        if net_scan:
            print(f"{Fore.GREEN}host {dst} is alived{Fore.RESET}")

        else:
            t2 = time.perf_counter()
            print(f"{Fore.GREEN}pinging {dst}, rtt is {str(t2-t1)[0:4]}{Fore.RESET}")
        return True
    else:
        if not net_scan:
            
            print (f"{Fore.BLUE}Timeout waiting for {packet[scapy.IP].dst}{Fore.RESET}")
        return False
    

def do_ping_till_break(dst):
    lossed  = 0
    answered = 0
    while True:
        try:
            if do_ping(dst, net_scan=False):
                answered += 1
            else:
                lossed += 1
            time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"{Fore.BLUE}{answered} packets are answered," 
                    f"and {lossed} packets are lossed.{Fore.RESET}")
            return


def check_online_hosts_in_a_range_auto(range):
    ans,unans = scapy.sr(scapy.IP(dst=range)/scapy.ICMP())
    ans.summary(lambda s,r: r.sprintf("%IP.src% is alive") )
    # ans,unans=sr( IP(dst="192.168.1.*")/TCP(dport=80,flags="S") )
    # ans.summary( lambda(s,r) : r.sprintf("%IP.src% is alive") )


def check_online_hosts_in_a_range_manual(ip_range):

    try:
        ip_list = [str(ip) for ip in ipaddress.ip_network(ip_range)]
        with mp.Pool(processes=32) as pool:
            pool.map(do_ping, ip_list)

        # for i in range(104,200):
        #     ip = "192.168.1.{ip}".format(ip=i)
        #     do_ping(ip)
        #     # else:
            #     print(f"{Fore.BLUE} {ip} [-] is down {Fore.RESET}")

    except Exception as e:
        print(Fore.RED + str(e) + Fore.RESET)


def check_port_range(target, start_range=1, stop_range=65535):
    flag = True
    t_IP = gethostbyname(target)
    print ('Starting scan on host: ', t_IP)

    for i in range(start_range, stop_range):
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(2)        
        conn = s.connect_ex((t_IP, i))
        if(conn == 0):
            flag = False
            print(f'Port {i}: open')
        s.close()
    if flag:
        print(f"{Fore.BLUE}no open ports found!{Fore.RESET}")


def check_port_range_nmap(target, start_range=1, stop_range=65535):
    nm = nmap.PortScanner()
    nm.scan(target, f'{start_range}-{stop_range}')
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            lport = sorted(lport)
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))   


def check_ip_range_nmap(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-n -sP -PE -PA21,22,23,80,443,3389")
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())


def do_ping_icmplib(dst):
    host = ping(dst, count=5, interval=0.2)
    if host.is_alive:
        print(f"{Fore.GREEN}pinging {dst}, avg rtt is {host.avg_rtt}")
        print(f"sent {host.packets_sent} packets, packet loss is {host.packet_loss} {Fore.RESET}")
    else:
        print(f"{Fore.GREEN}pinging {dst}, host is down {Fore.RESET}")


def scan_range_icmplib(ip_range):
    flag = True
    ip_list = [str(ip) for ip in ipaddress.ip_network(ip_range)]
    hosts = multiping(ip_list,count=2, interval=0.5, timeout=2, concurrent_tasks=50)
    for host in hosts:
        if host.is_alive:
            flag = False
            print(f"{Fore.GREEN}host {host.address} is up! {Fore.RESET}")
    if flag:
        print(f"{Fore.BLUE}no online host available!{Fore.RESET}")


###########################################MAIN#####################################


if __name__ == "__main__":
    try:
        args = parser.parse_args()
        if args.ping:
            if args.till_break:
                do_ping_till_break(args.string)
            else:
                do_ping_icmplib(args.string)
        elif args.scan_range:
            # check_ip_range_nmap(args.string)
            if IPChecker.is_ipv4_range_valid(range=args.string):
                scan_range_icmplib(args.string)
            else:
                print(f"{Fore.YELLOW}enter a valid ip{Fore.RESET}")
        elif args.scan_port:
            check_port_range_nmap(args.string, args.start, args.end)
            # check_port_range(args.string, args.start, args.end)
    except KeyboardInterrupt:
        print(f"{Fore.BLUE}User sent sig-term!{Fore.RESET}")
