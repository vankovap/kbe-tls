from Cryptodome.Hash import SHA1

# calculate the key to be used in AES
def secret_to_128key(key):
    h = SHA1.new()
    h.update(key)
    return h.digest()[:16]


def txt2bin(value):
    return value.encode('utf-8')


def hex2bin(value):
    return bytearray.fromhex(value)


def int2bytes(value):
    bytes_val = value.to_bytes(2048, 'big')
    return bytes(filter(None, bytes_val))


def bytes2int(value):
    return int.from_bytes(value, 'big')
