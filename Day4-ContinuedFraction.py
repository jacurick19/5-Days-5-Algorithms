'''
This module implements a toy encryption algorithm in which a sequence of bytes
is identified with a rational number in the following way.

The PLAINTEXT is a sequence of bytes b_0, b_1, ..., b_{n-1}. Considering each
byte as the unsigned binary representation of an integer, we have a
corresponding sequence of positive integers c_0, c_1, ..., c_{n-1} (each in the
range 0-255, inclusive). The CIPHERTEXT is the rational number whose continued
fraction is [{c_0} + 2; {c_1} + 2, {c_2} + 2, ..., {c_{n-1}} + 2] (expressed
here in standard continued fraction notation).

The "+2" is necessary to ensure during encryption that there is no ambiguity in
the sequence of coefficients of the number's continued fraction. If "+1" were
used instead, then it would be impossible to tell the difference between a
length-n ciphertext sequence ending in ..., y, z and a length-{n+1} ciphertext
sequence ending in ..., y, z-1, z+1.

Chris Kimmel
7-17-2021
chris.kimmel@live.com
'''

# pylint: disable=invalid-name


from fractions import Fraction
from math import floor
from random import randrange, seed
from unittest import TestCase


NONPOS_ERRMESS = 'This subroutine can only compute continued fractions of '\
                 'positive numbers.'

NO_PLAINTEXT_ERRMESS = 'This fraction does not correspond to any sequence of '\
                       'plaintext bytes.'


def encrypt_cont_frac(plaintext):
    '''
    Arguments:
        plaintext (bytes)
    Returns:
        ciphertext (Fraction)
    Requires:
        len(plaintext) > 0
    '''
    assert plaintext, "This algorithm cannot encrypt an empty string"
    first_byte, the_rest = plaintext[0], plaintext[:-1]
    leading_int = Fraction(int.from_bytes(first_byte, 'little', 'unsigned'))
    if the_rest:
        retval = leading_int + 1/encrypt_cont_frac(the_rest)
    else:
        retval = leading_int
    return retval


def decrypt_cont_frac(ciphertext):
    '''
    Arguments:
        ciphertext (Fraction)
    Returns:
        plaintext (bytes)
    Requires:
        ciphertext is > 1, and all coefficients in its canonical continued
            fraction representation are >= 2
    '''
    the_cont_frac = cont_frac(ciphertext)
    assert all(x >= 2 for x in the_cont_frac), NO_PLAINTEXT_ERRMESS
    return b''.join((x-2).to_bytes(1, 'little', 'unsigned') for x in ciphertext)


def cont_frac(x):
    '''
    Compute the canonical continued-fraction representation of the positive
    rational number x. For example, cont_frac(Fraction(7/3)) should return
    [2, 3]. (In standard notation this is the continued fraction [2; 3].)

    Arguments:
        x (Fraction)
    Returns:
        cont_frac (list of positive integers)
    Requires:
        frac > 0
    '''
    assert x > 0, NONPOS_ERRMESS
    integer_part = floor(x)
    fractional_part = x - integer_part
    return [integer_part] + cont_frac(1/fractional_part) if fractional_part \
        else [integer_part]


def get_random_bytes(length, seedval):
    '''Return a random bytes object of specified length.'''
    seed(seedval)
    return b''.join(
        randrange(256).to_bytes(1, byteorder='little', signed=False)
        for _ in range(length)
    )


class TestContFrac(TestCase):
    '''Test cont_frac() subroutine.'''
    # pylint: disable=missing-docstring

    def test_okay(self):
        l = [(Fraction(7, 3), [2, 3]),
             (Fraction(5, 2), [2, 2]),
             (Fraction(1, 2), [0, 2]),
             (Fraction(5, 8), [0, 1, 1, 1, 1])]
        for t in l:
            ans = cont_frac(t[0])
            exp = l[1]
            self.assertEqual(ans, exp, t[0])

    def test_failure(self):
        l = (Fraction(x)/120 for x in range(-240, 1))
        for t in l:
            with self.assertRaises(NONPOS_ERRMESS):
                _ = cont_frac(t)


class TestEncrypt(TestCase):
    '''Test encrypt_cont_frac() subroutine.'''
    # pylint: disable=missing-docstring

    def test_easy(self):
        l = [(Fraction(7, 3), b'\x02\x03'),
             (Fraction(5, 2), b'\x02\x02')]
        for t in l:
            ans = decrypt_cont_frac(t[0])
            exp = t[1]
            self.assertEqual(ans, exp, t[0])


class TestDecrypt(TestCase):
    '''Test decrypt_cont_frac() subroutine.'''
    # pylint: disable=missing-docstring

    def test_easy(self):
        l = [(Fraction(7, 3), b'\x02\x03'),
             (Fraction(5, 2), b'\x02\x02')]
        for t in l:
            ans = decrypt_cont_frac(t[0])
            exp = t[0]
            self.assertEqual(ans, exp, t[0])

    def test_impossible(self):
        with self.assertRaises(NONPOS_ERRMESS):
            _ = decrypt_cont_frac(Fraction(0))
        with self.assertRaises(NONPOS_ERRMESS):
            _ = decrypt_cont_frac(Fraction(-1))
        with self.assertRaises(NO_PLAINTEXT_ERRMESS):
            _ = decrypt_cont_frac(Fraction(5, 8))


class TestTogether(TestCase):
    '''Test encryption and decryption subroutines together as a system.'''
    # pylint: disable=missing-docstring

    def test_fuzz(self):
        for i in range(0, 50):
            plaintext = get_random_bytes(length=10**6, seedval=i)
            ciphertext = encrypt_cont_frac(plaintext)
            new_plaintext = decrypt_cont_frac(ciphertext)
            self.assertEqual(plaintext, new_plaintext)
