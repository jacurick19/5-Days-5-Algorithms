'''
This module contains a toy encryption tool based on the quasidihedral group of
order 256.

We use this group presentation throughout:
        G = < r, s | r^{2^{n-1}} = s^2 = 1, sr = r^{2^{n-2}-1}s >
In our case n = 8 and resulting group has order |G| = 2^n = 256.

Every element of G is uniquely representable in the form (r^k)(s^j)
for k an integer in the range 0, ..., 127 and j either 0 or 1. For any byte b,
the most significant bit of b is interpreted as j and the least significant 7
bits are interepreted as the binary representation of k. In this manner, bytes
are identified with elements of G.

As an example of our conventions (using unsigned integer representations of
byte strings), we have
    128 * 3 = 10000000 * 00000011
            = s * r^3
            = r^63 * s
            = 10011111
            = 191

See Testcases.test_known_message for a usage example.

Chris Kimmel
7-15-2021
chris.kimmel@live.com
'''

from io import BytesIO
from random import seed, randrange
from unittest import TestCase


# pylint: disable=invalid-name


def quasidihedral_256_times(a, b):
    '''
    Arguments:
        a, b (bytes): unsigned bytes representing an element of G
    Returns:
        c (bytes): unsigned bytes representing the product ab
    Requires:
        len(a) == len(b) == 1
    Ensures:
        len(c) == 1
    '''
    a, b = int.from_bytes(a, 'little', signed=False), int.from_bytes(b, 'little', signed=False)
    k1, k2 = a % 128, b % 128
    j1, j2 = (a >> 7) & 1, (b >> 7) & 1

    retval_j = j1 ^ j2
    retval_k = (k1 + 63*k2) % 128 if j1 else (k1 + k2) % 128
    retval = 128*retval_j + retval_k

    return retval.to_bytes(1, 'little', signed=False)


def quasidihedral_256_inverse(a):
    '''
    Arguments:
        a (bytes): unsigned bytes representing an element of G
    Returns:
        b (bytes): unsigned bytes representing the inverse of a
    Requires:
        len(a) == 1
    Ensures:
        len(b) == 1
    '''
    a = int.from_bytes(a, 'little', signed=False)
    k, j = a % 128, (a & 128)
    retval = 128 + (63*(128 - k) % 128) if j else (128 - k) % 128
    retval = retval.to_bytes(1, 'little', signed=False)
    return retval


IDENTITY = (0).to_bytes(1, 'little', signed=False)
S = (128).to_bytes(1, 'little', signed=False)
R = (1).to_bytes(1, 'little', signed=False)


def stream_encryptor(input_stream, output_stream):
    '''
    Encrypt input_stream to output_stream.

    Arguments:
        input_stream (io.BytesIO)
        output_stream (io.BytesIO)

    This method sets output_stream[x] equal to the product of the elements in
    the slice input_stream[0:x+1]. Naturally, input_stream[0] is on the left of
    the word and output_stream[x] is on the right of the word, with respect to
    the conventions followed in the rest of this module.
    '''
    running_product = IDENTITY
    while True:
        byte = input_stream.read(1)
        if byte:
            running_product = quasidihedral_256_times(running_product, byte)
            output_stream.write(running_product)
        else:
            break


def stream_decryptor(input_stream, output_stream):
    '''
    Decrypt output_stream to input_stream.
    '''
    last_element = IDENTITY
    while True:
        byte = input_stream.read(1)
        if byte:
            output_stream.write(quasidihedral_256_times(
                quasidihedral_256_inverse(last_element), byte))
            last_element = byte
        else:
            break


def get_random_bytes(length):
    '''
    Return a random bytes object of specified length
    '''
    return b''.join(
        randrange(256).to_bytes(1, byteorder='little', signed=False)
        for _ in range(length)
    )


class Tests(TestCase):
    # pylint: disable=missing-function-docstring,missing-class-docstring

    def test_identity_law(self):
        for x in range(256):
            x = x.to_bytes(1, 'little', signed=False)
            id_x = quasidihedral_256_times(IDENTITY, x)
            x_id = quasidihedral_256_times(x, IDENTITY)
            self.assertEqual(id_x, x)
            self.assertEqual(x_id, x)

    def test_inverse_law(self):
        for x in range(256):
            x = x.to_bytes(1, 'little', signed=False)
            inv = quasidihedral_256_inverse(x)
            prod = quasidihedral_256_times(x, inv)
            self.assertEqual(prod, IDENTITY, str(x))

    def test_known_message(self):
        plaintext_bytes = b'I know how to outpizza the hut'
        plaintext_stream = BytesIO(plaintext_bytes)
        ciphertext_stream = BytesIO()
        stream_encryptor(plaintext_stream, ciphertext_stream)
        ciphertext_stream.seek(0)
        decrypted_stream = BytesIO()
        stream_decryptor(ciphertext_stream, decrypted_stream)
        decrypted_stream.seek(0)
        decrypted_bytes = decrypted_stream.read()
        self.assertEqual(plaintext_bytes, decrypted_bytes)

    def test_fuzz(self):
        for s in range(20):
            seed(s)
            initial_plaintext = BytesIO(get_random_bytes(1000))
            ciphertext = BytesIO()
            final_plaintext = BytesIO()

            stream_encryptor(initial_plaintext, ciphertext)
            ciphertext.seek(0)
            stream_decryptor(ciphertext, final_plaintext)

            initial_plaintext.seek(0)
            final_plaintext.seek(0)
            self.assertEqual(initial_plaintext.read(), final_plaintext.read())

    def test_subgroup_of_order_2(self):
        for i1 in range(2):
            for i2 in range(2):
                s1 = (128*i1).to_bytes(1, 'little', signed=False)
                s2 = (128*i2).to_bytes(1, 'little', signed=False)
                ans = quasidihedral_256_times(s1, s2)
                exp = (128*int(bool(i1) ^ bool(i2))).to_bytes(1, 'little', signed=False)
                self.assertEqual(ans, exp, f"{s1} * {s2}")

    def test_subgroup_of_order_128(self):
        for i1 in range(0, 128):
            for i2 in range(0, 128):
                r1 = i1.to_bytes(1, 'little', signed=False)
                r2 = i2.to_bytes(1, 'little', signed=False)
                ans = quasidihedral_256_times(r1, r2)
                exp = ((i1 + i2) % 128).to_bytes(1, 'little', signed=False)
                self.assertEqual(ans, exp, f"{r1} * {r2}")

    def test_conjugator(self):
        '''Conjugate powers of R by S'''
        for i1 in range(0, 128):
            r_to_the_i1 = i1.to_bytes(1, 'little', signed=False)
            p = quasidihedral_256_times(S, r_to_the_i1)
            ans = quasidihedral_256_times(p, S)
            exp = ((63*i1) % 128).to_bytes(1, 'little', signed=False)
            self.assertEqual(ans, exp, f"{i1}")
