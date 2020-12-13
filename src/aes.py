from Cryptodome.Cipher import AES
import helpers as fn
BLOCK_SIZE = 16


# add PKCS#1 padding
def pad(x):
    if type(x) is str:
        data_bin = fn.txt2bin(x)
    else:
        data_bin = x
    pad_length = BLOCK_SIZE - (len(data_bin) % BLOCK_SIZE)
    pad_string = format(pad_length, "x").rjust(2, '0')
    for i in range(pad_length):
        data_bin += bytes(fn.hex2bin(pad_string))
    return data_bin


# remove PKCS#1 padding
def unpad(y):
    pad_length = y[-1]
    return y[:-pad_length]


def encrypt(key, iv, message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8')))
    return iv + ciphertext


def decrypt(key, iv, message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(message[BLOCK_SIZE:])
    return unpad(plaintext).decode('utf-8')


