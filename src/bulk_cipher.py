import random
import string
import os
import aes

BLOCK_SIZE = 16

key = os.urandom(BLOCK_SIZE)
iv = os.urandom(BLOCK_SIZE)
msg = ''.join(random.choice(string.ascii_lowercase) for i in range(1024))
assert aes.decrypt(key, iv, aes.encrypt(key, iv, msg)) == msg