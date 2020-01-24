'''
    author : zerobits01
    created: 24-Jan-2020
    purpose: scanning the network and discover all other
                connected devices IP and mac-address
'''

# we can use python nmap module(lib) too but, am trying to
# implement my own net-scanner

import scapy.all as scapy
import argparse
import asyncio
import functools



def force_async(fn):
    '''
    turns a sync function to async function using threads
    '''
    from concurrent.futures import ThreadPoolExecutor
    import asyncio
    pool = ThreadPoolExecutor()

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        future = pool.submit(fn, *args, **kwargs)
        return asyncio.wrap_future(future)  # make it awaitable

    return wrapper



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
result = None

def net_scan_auto(ip):
    # using scapy.arping we gonna use arp protocol to find out macs
    # this method does the job automatically
    scapy.arping(ip)

@force_async
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
    global result
    result = [{'ip' : node[1].pdst,'mac' : node[1].hwdst} for node in nodes]

def print_result(nodes):
    print()
    print('ip\t\t\tmac')
    print('-------------------------------------')
    for node in nodes :
        print(node['ip'],node['mac'], sep='\t')

async def scan():
    try :
        global result
        print('[!] please wait.')
        # scan_task = asyncio.create_task(net_scan_manually(args.range))
        # done, _ = await asyncio.wait(scan_task)
        await net_scan_manually(args.range)
        print_result(result)
        print('[+] done as well.')
    except Exception as e:
        print(e)
        print('[-] sorry something unexpected happened.')

async def printWait():
    import time
    global result
    counter = 0
    while result is None:
        time.sleep(0.25)
        string = '.' if counter == 0 else '..' if counter == 1 else '...'
        print('\b\r[!]sending requests' + string + ' ', end='')
        counter = counter + 1 if counter <= 2 else 0

async def main():
    await asyncio.gather(scan(),printWait())

# net_scan_auto('192.168.1.1/24')
if __name__ == '__main__':
    asyncio.run(main())
    # net_scan_auto(args.range)