import argparse
import re
import subprocess

string = '''
    author : zerobits01
    purpose: increasing anonymity
    email  : zerobits01@yahoo.com
    gmail  : zerobits0101@gmail.com
    team   : Paradox-Squad
    description : simply use this app to change your NIC mac-addr

'''
simple_usage = "python mac_changer.py -n eth0 -m 00:11:22:33:44:55"

parser = argparse.ArgumentParser(description=string + simple_usage)

parser.add_argument('-n','--nic',dest='nic',
                        help="network interface card name e.g : eth0,wlan0",
                            type=str, required=True)

parser.add_argument('-m','--mac',dest='mac',
                        help="new mac-addr for the nic entered, pattern xx:xx:xx:xx:xx:xx",
                            type=str, required=True)

args = parser.parse_args()

class InputExcpetion(Exception):
    def __init__(self, msg):
        self.msg = msg
        
class SystemException(Exception):
    def __init__(self, msg):
        self.msg = msg


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