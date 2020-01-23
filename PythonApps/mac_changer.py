import argparse
import re
import subprocess
import random
import string
import os
import binascii




parser = argparse.ArgumentParser(description='\tauthor : zerobits01\n' 
    '\tpurpose: increasing anonymity\n'
    '\temail  : zerobits01@yahoo.com\n'
    '\tgmail  : zerobits0101@gmail.com\n'
    '\tteam   : Paradox-Squad\n'
    '\tdescription : use this app to change your NIC mac-addr\n'
            '\tthis just work on unix-base OS\n', formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-n','--nic',dest='nic',
                        help="network interface card name e.g : eth0,wlan0",
                            type=str, required=True)

newmac = parser.add_mutually_exclusive_group(required=True)

newmac.add_argument('-m','--mac',dest='mac',
                        help="new mac-addr for the nic entered, pattern xx:xx:xx:xx:xx:xx",
                            type=str)
newmac.add_argument('-rm','--random',dest='randomized',
                        action='store_true',
                            default=False,
                                help="randomly generate a new mac")
args = parser.parse_args()

class InputExcpetion(Exception):
    def __init__(self, msg):
        self.msg = msg
        
class SystemException(Exception):
    def __init__(self, msg):
        self.msg = msg



def randomMac():
    # to generate a random mac
    base = "02:00:00"
    res = binascii.b2a_hex(os.urandom(12))
    res = res.decode('utf-8')
    # random_mac = ':'.join([str(res[n]) + str(res[n+1]) for n in (0,2,4,6,8,10)])
    random_mac = base + ":%02x:%02x:%02x" % (random.randint(0, 255),
                             random.randint(0, 255),
                             random.randint(0, 255))
    return random_mac



def checkArgs(rndm=None):
    # checking input
    global args
    matched = re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",args.mac)
    if matched :
        return
    else :
        raise InputExcpetion(msg="[-] couldn't change mac. bad input")

def changeMac():
    # changing mac-addr
    global args
    try :
        if args.randomized :
            rndmmac = randomMac()
            subprocess.call(['ifconfig', args.nic, 'down']) 
            subprocess.call(['ifconfig', args.nic, 'hw', 'ether', rndmmac])
            x = subprocess.call(['ifconfig', args.nic, 'up'])
            if x != 0:
                raise SystemException(msg="[-] couldn't change mac. system problem")
        else :
            checkArgs()
            subprocess.call(['ifconfig', args.nic, 'down']) 
            subprocess.call(['ifconfig', args.nic, 'hw', 'ether', args.mac])
            x = subprocess.call(['ifconfig', args.nic, 'up'])
            if x != 0 :
                raise SystemException(msg="[-] couldn't change mac. system problem")
    except Exception:
        raise SystemException(msg="[-] couldn't change mac. system problem")

def main() :
    # running the all commands above
    try : 
        changeMac()
    except SystemException as e:
        print(e.msg)
    except InputExcpetion as e :
        print(e.msg)
    except Exception as e :
        print('[-] couldn\'t change mac') 
    else :
        print("[+] mac changed successfully.")

if __name__ == '__main__' :
    main()