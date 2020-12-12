# TLS protocol

## Task 1: Diffie–Hellman key exchange
Implementation of this task is in the file `dh.py`, since the exchange algorithm itself is a part of the Agent class, this file contains only the basic calculations.

Tests are in the file `dh_test.py`.

## Task 2: Diffie–Hellman key 
Implemented in `helpers.py`.

## Task 3: Bulk cipher
Implemented in `aes.py` with custom functions for padding and unpadding, encryption and decryption.
Checked with ``bulk_cipher.py`` example.

## Task 4: Implement simple SSL/TLS setup
Implemented in `agent.py`, implementation checked with `tls_101.py`.

## Task 5: Man-in-the-middle
Implemented in `mitm.py`, implementation checked with `itls_101.py`. 

## Task 6: RSA
Implemented in `rsa.py` with tests in `rsa_test.py`.
## Task 7:  RSA broadcast attack
Implemented in `rsa.py` as well, tests also in `rsa_test.py`. Files `test_message` and `message_captured` used in the tests. 

How Chinese remainder theorem is helping you here?

* this attack is based on the usage of small `e` and the fact that when an eavesdropper is able to capture at least three cipher texts of the same message `m`, they are able to "decrypt" it with CRT
* Because we know the remainder of the encrypted `m^e`  modulo three different prime numbers (`n1`, `n2`, `n3`), using the CRT we are able to compute `c' = m^e mod n1*n2*n3`. Since `m^e < n1*n2*n3` we can compute `e`-th root of `m` in integers.

## Task 8: Bleichenbacher's RSA attack

Not implemented.

## Task 9: DSA 

Not implemented.

## Task 10 (Bonus): DSA domain parameters
Not implemented.