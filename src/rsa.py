import math
import helpers as fn
import json


def ext_eucl(a, b):
    swapped = False
    if b > a:
        pom = a
        a = b
        b = pom
        swapped = True
    u, v, r = 0, 1, b
    u_prev, v_prev, r_prev = 1, 0, a
    while r > 0:
        q = r_prev // r
        r_prev, r = r, r_prev - q * r
        u_prev, u = u, u_prev - q * u
        v_prev, v = v, v_prev - q * v
    if swapped:
        return r_prev, v_prev, u_prev
    else:
        return r_prev, u_prev, v_prev


def read_file(file):
    with open(file) as in_file:
        data = in_file.readlines()
    return data


# this function is inspired by a code I found, but I totally forgot where
def cube_root(x):
    upper = 1
    while upper ** 3 <= x:
        upper *= 2
    lower = upper // 2
    while lower < upper:
        mid = (lower + upper) // 2
        mid_3rd = mid ** 3
        if lower < mid and mid_3rd < x:
            lower = mid
        elif upper > mid and mid_3rd > x:
            upper = mid
        else:
            return mid
    return mid + 1


class RSA:
    def __init__(self, p, q, e):
        self.e = e
        self.p = p
        self.q = q
        self.n = self.p * self.q
        self.fi_n = abs((self.p - 1) * (self.q - 1))
        self.d = self.invmod(self.e, self.fi_n)

    def invmod(self, a, m):
        if math.gcd(a, m) != 1:
            return None
        else:
            mod = ext_eucl(a, m)
            return mod[1] % m

    def encrypt_int(self, int_):
        ciphertext = pow(int_, self.e, self.n)
        return ciphertext

    def decrypt_int(self, encrypted_int):
        return pow(encrypted_int, self.d, self.n)

    def encrypt(self, msg):
        ciphertext = self.encrypt_int(fn.bytes2int(msg))
        return fn.int2bytes(ciphertext)

    def decrypt(self, encrypted_msg):
        plaintext = self.decrypt_int(fn.bytes2int(encrypted_msg))
        return fn.int2bytes(plaintext)


class SimpleHastadAttack:
    def __init__(self, data):
        msgs = read_file(data)
        self.messages = []
        index = 0
        for i in msgs:
            msg = json.loads(i)
            msg["index"] = index
            self.messages.append(msg)
            index += 1

    def get_message(self):
        ciphertext = 1
        mod = 1
        for i in self.messages:
            ciphertext *= i["data"]
            mod *= i["n"]
        # compute quotients
        for i in self.messages:
            t = 1
            q = 1
            for j in self.messages:
                if j["index"] != i["index"]:
                    q *= j["n"]
                    t *= (j["n"] % i["n"])
            inv = ext_eucl(t, i["n"])[1]
            q *= inv % i["n"]
            i["q"] = q
        x = 0
        for i in self.messages:
            x += i["q"]*i["data"]
        return cube_root(x % mod)

