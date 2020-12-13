import rsa
import helpers as fn

def test():
    p = 13604067676942311473880378997445560402287533018336255431768131877166265134668090936142489291434933287603794968158158703560092550835351613469384724860663783
    q = 20711176938531842977036011179660439609300527493811127966259264079533873844612186164429520631818559067891139294434808806132282696875534951083307822997248459
    r = rsa.RSA(p, q, 3)
    # test invmod function
    assert r.invmod(3, 11) == 4
    assert r.invmod(19, 1212393831) == 701912218
    assert r.invmod(13, 91) is None

    # test rsa encrypt and decrypt (int only)
    r2 = rsa.RSA(11, 113, 3)
    assert r2.encrypt_int(7) == 343
    assert r2.encrypt_int(21) == 560
    assert r2.decrypt_int(400) == 478
    assert r2.decrypt_int(3) == 372

    # test rsa encrypt, decrypt of bytes
    msg = 'HelloWorld'
    plaintext = r.decrypt(r.encrypt(msg.encode()))
    assert plaintext.decode() == msg

    # test extended euclidean algorithm
    assert rsa.ext_eucl(270, 192)[0] == 6
    # test simple Hastad Attack
    attack = rsa.SimpleHastadAttack('test_message')
    assert attack.get_message() == 123
    # get the real message
    attack = rsa.SimpleHastadAttack('message_captured')
    print(fn.int2bytes(attack.get_message()).decode())





if __name__ == "__main__":
    test()
