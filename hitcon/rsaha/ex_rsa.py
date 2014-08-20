"""
Solution to rsaha (HITCON CTF 2014)

Author: clu (notclu@gmail.com)
"""

import socket
import re
import libnum

HOST = '54.64.40.172'
PORT = 5454

def parse_data(data):
    return [int(m) for m in re.findall('^(\d+)',data, re.MULTILINE)]

def recv_next_nums(s):
    data_out = ''
    while True:
        data = s.recv(1024)
        data_out += data

        try:
            nums = parse_data(data_out)
            if len(nums) == 3:
                return (nums,data_out)
        except:
            pass

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# We need to break 10 RSA encryptions before the server will send
# us the flag RSA encrypted
i=0
while True:
    print('-----------------')
    print(i)
    print('-----------------')
    nums,data = recv_next_nums(s)
    print(data)

    n = nums[0]
    c1 = nums[1]
    c2 = nums[2]

    # Turns out if messages encrypted with RSA have a linear
    # relationship (in this case m2=m1+1) there is an efficent
    # algorithm to decrypt the messages.
    #
    # The equation for e=3 is (c2 + 2c1 - 1) * (c2-c1+2)^-1 mod N
    #
    # See the paper Low-Exponent RSA with Related Messages
    # (https://www.cs.unc.edu/~reiter/papers/1996/Eurocrypt.pdf)
    top = (c2 + 2*c1 -1) %n
    bot = libnum.invmod(c2 - c1 + 2, n)
    m = top*bot%n

    # Send out the message and wait for the next one. The last  decrypted message
    # is flag. The socket will be closed by that point so we can
    # take the number convert it to an ascii string and submit
    print('m=%d' % m)
    s.sendall('%d\n' % m)

    i=i+1
