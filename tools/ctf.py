import time
import socket
import hexdump

def shell(host, port, tries=10, verbose=True):
    if verbose:
        print('Attempting to connect to shell @ %s:%d' % (host,port))
    shell_conn = None

    for i in range(0,tries):
        if verbose:
            print(i)
        try:
            shell_conn = connect(host, port)
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

def recv(sock, recv_len=1024, dump=True):
    data = sock.recv(recv_len)
    print("\nReceived len=%d (0x%X)\n<<<<<<<<<<<<<<<\n" % (len(data), len(data)))
    if dump:
        hexdump.hexdump(data)
    else:
        print(data)
    return data


def send(sock, data, dump=True):
    sock.sendall(data)
    print("\nSent len=%d (0x%X)\n>>>>>>>>>>>>>>>>\n" % (len(data), len(data)))
    if dump:
        hexdump.hexdump(data)
    else:
        print data

def connect(host,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def chunks(l, n, adv=None):
    """ Yield successive n-sized chunks from l.
    """
    if not adv:
        adv = n

    for i in xrange(0, len(l), adv):
        yield l[i:i+n]
