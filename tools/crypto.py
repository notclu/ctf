import ctf

def do_xor(a, b):
    out = ''
    for a_byte, b_byte in zip(a,b):
        out += chr(ord(a_byte) ^ ord(b_byte))

    return out

def get_most_common_bytes(data, block_size):
    counts = [[0 for i in range(0,256)] for j in range(0,256)]

    for c in ctf.chunks(data, block_size):
        for i,d in enumerate(c):
            val = ord(d)
            counts[i][val] = counts[i][val] + 1

    max_vals = []

    for c in counts:
        max_vals.append(c.index(max(c))) 
