'''
    author  : zerobits01
    created : 25-Jan-2020
    modified: 28-Jan-2020
    purpose : listener pool for all clients and gives a remote terminal
                to client
'''

import socket
import json
import threading

HOST = lambda : '0.0.0.0'
PORT = lambda : '0101'

all_sockets = []

class SocketHandler(threading.Thread):

    def __init__(self,id,name,addr,conn):
        threading.Thread.__init__()
        self.leave = False
        self.id = id

        self.name = name

        self.addr = addr
        self.conn = conn

    def saveFile(self):
        # TODO : get json data and write it binary
        pass

    def upload(self):
        # TODO : get the path read the file and return json string
        pass

    def sessionChoice(self):
        # TODO : get session address(giving some info) and returning id to choose
        pass

    def disconnect(self):
        self.leave = True

    def run(self) -> None:
        while self.leave != True :
            pass
        print('[*] %s disconnected'%(self.name))

class Handler(threading.Thread):

    def __init__(self):
        threading.Thread.__init__()

    def run(self) -> None:
        # TODO : handling user input and accessing other threads
        global all_sockets
        prompt = 'zbits'
        while True :
            # TODO : check the prompt
            connected = input(prompt + '> ') # TODO : naming OS@session#>


while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s :
        s.bind((HOST(),PORT()))
        s.listen()
        id = 0
        Handler()
        while True:
            conn, addr = s.accept()
            all_sockets.append(
                SocketHandler(id=id,name='session %d'%(id),addr=addr,conn=conn))
            id += 1

'''
    data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)
'''