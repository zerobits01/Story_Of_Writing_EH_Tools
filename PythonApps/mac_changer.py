import argparse
import re
import subprocess
import random
import string





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
    choices = string.digits + string.ascii_lowercase
    res = [random.choice(choices) for x in range(12)]
    random_mac = ':'.join([str(res[n]) + str(res[n+1]) for n in (0,2,4,6,8,10)])
    return random_mac



def checkArgs():
    # checking input
    global args
    matched = re.search(r"(([0-9a-zA-Z]){2}:){5}([0-9a-zA-Z]){2}",args.mac)
    if matched :
        return
    else :
        raise InputExcpetion(msg="[-] couldn't change mac. bad input")

def changeMac():
    # changing mac-addr
    global args
    try :
        if args.randomized : 
            subprocess.call(['ifconfig', args.nic, 'down']) 
            subprocess.call(['ifconfig', args.nic, 'hw', 'ether', randomMac()])
            subprocess.call(['ifconfig', args.nic, 'up'])
        else :
            subprocess.call(['ifconfig', args.nic, 'down']) 
            subprocess.call(['ifconfig', args.nic, 'hw', 'ether', args.mac])
            subprocess.call(['ifconfig', args.nic, 'up'])
    except Exception:
        raise SystemException(msg="[-] couldn't change mac. system problem")

def main() :
    # running the all commands above
    try : 
        checkArgs()
        changeMac()
    except SystemException as e:
        print(e.msg)
    except InputExcpetion as e :
        print(e.msg)
    except Exception as e :
        print() 
    else :
        print("[+] mac changed successfully.")

if __name__ == '__main__' :
    main()