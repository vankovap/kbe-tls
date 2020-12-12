def public_key(secret, modulus, base):
    key = base ** secret % modulus
    return key


def calculate_shared_key(pub_key, secret, modulus):
    shared_key = pub_key ** secret % modulus
    return shared_key


