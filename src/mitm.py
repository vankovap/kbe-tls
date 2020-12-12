import random
import sys
import dh
import aes
import helpers as fn


class MITM:
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    def __init__(self):
        self.secret = random.randint(1, 10000)
        self.msg = None
        self.shared_key_A = None
        self.shared_key_B = None

    def send_public_data(self):
        public = [self.p, self.g]
        return public

    def receive_public_data(self, *data):
        if (data[0] != self.p) or (data[1] != self.g):
            sys.exit('I do not agree with these parameters! Aborting...')

    def send_public_key(self):
        return dh.public_key(self.secret, self.p, self.g)

    def receive_public_key(self, key):
        key = dh.calculate_shared_key(key, self.secret, self.p)
        if self.shared_key_A is None:
            self.shared_key_A = fn.secret_to_128key(fn.int2bytes(key))
        else:
            self.shared_key_B = fn.secret_to_128key(fn.int2bytes(key))

    def intercept_message(self, msg):
        iv = msg[:aes.BLOCK_SIZE]
        plaintext = aes.decrypt(self.shared_key_A, iv, msg)
        self.msg = plaintext
        ciphertext = aes.encrypt(self.shared_key_B, iv, plaintext)
        return ciphertext
