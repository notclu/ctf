class my_bytes:
   def __init__(self, data):
      try:
         self.data = bytearray(data.decode('hex'))
      except:
         self.data = data
   def __iter__(self):
      return self.data.__iter__()
   def __str__(self):
      return ''.join('{0:X}'.format(byte) for byte in self.data)
   def __len__(self):
      return len(self.data)
   def __getitem__(self, key):
      return self.data[key]
   def __xor__(self, other):
      return my_bytes(bytearray((x ^ y) for (x, y) in zip(self.data, other.data)))

# Chances are the decrypted plain text character will be a letter or a space
# Return the number of ciphertexts where the guess decrypts to a letter or space
def check_guess(decrypt_fn, ct_bytes, guess):
   correct = 0
   for byte in ct_bytes:
      letter = decrypt_fn(byte, guess)
      
      if letter.isalpha() or letter.isspace():
         correct = correct + 1
   return correct
   
# decrypt_fn example: def do_decrypt(byte, key)
def guess_key(ct, pos, decrypt_fn, adj_table={}):
   # Get all the bytes at pos (ie the column of bytes in all the ciphertexts)
   ct_bytes = [ctext[pos] for ctext in ct if len(ctext) > pos ]

   # Basically just brute force the key byte-by-byte. The key byte that decrypts to the
   # most ASCII characters is probably the right byte.
   if pos not in adj_table:
      guess_table = [check_guess(decrypt_fn, ct_bytes, i) for i in range(0,256)]

      key_byte = guess_table.index(max(guess_table))
   else:
      # If we want to adjust the output find the key byte that
      # results in the correct plaintext byte and has the most
      # ASCII chars in the result
      key_byte = None
      best = 0
      for i in range(0,256):
         if decrypt_fn(ct_bytes[adj_table[pos][0]], i) == adj_table[pos][1]:
            if check_guess(decrypt_fn, ct_bytes, i) > best:
               best = check_guess(decrypt_fn, ct_bytes, i)
               key_byte = i

   return key_byte

def decrypt_reused_key(ciphertexts, decrypt_fn, adjust_table={}):
   max_ct_len = max([len(c) for c in ciphertexts])
   the_key = [guess_key(ciphertexts, i, decrypt_fn, adjust_table) for i in range(max_ct_len)]

   plaintexts = []
   for ct in ciphertexts:
      plaintexts.append(''.join(decrypt_fn(byte, key_byte) for byte, key_byte in zip(ct, the_key)))

   return plaintexts
