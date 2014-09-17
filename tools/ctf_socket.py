import re
import time
import socket
import hexdump

class CTFSocket(object):
    def __init__(self, host, port, dump=True):
        self.dump = dump
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

    def recv(self, recv_len=1024, dump=None):
        data = self.sock.recv(recv_len)
        print("\nReceived len=%d (0x%X)\n<<<<<<<<<<<<<<<\n" % (len(data), len(data)))

        dump = dump if dump else self.dump
        if dump:
            hexdump.hexdump(data)
        else:
            print(data)

        return data

    def recv_until(self, regex, dump=None):
        data = self.recv(dump=dump)

        while not re.search(regex, data):
            data += self.recv(dump=dump)

        return data

    def send(self, data, dump=True):
        self.sock.sendall(data)

        print("\nSent len=%d (0x%X)\n>>>>>>>>>>>>>>>>\n" % (len(data), len(data)))

        dump = dump if dump else self.dump
        if dump:
            hexdump.hexdump(data)
        else:
            print data

def shell(host, port, tries=10, verbose=True):
    if verbose:
        print('Attempting to connect to shell @ %s:%d' % (host,port))
    shell_conn = None

    for i in range(0,tries):
        if verbose:
            print(i)
        try:
            shell_conn = CTFSocket(host, port, dump=False)
            break
        except socket.error:
            if i+1 < tries:
                time.sleep(1)

    if shell_conn:
        print('Got it!')
        command=''
        while(command != 'exit'):
            command=raw_input('$ ')
            shell_conn.send(command + '\n')#raw_input won't grab a newline
            print(shell_conn.recv(0x10000))

        shell_conn.close()
    else:
        if verbose:
            print("Couldn't connect to %s:%d" % (host,port))





