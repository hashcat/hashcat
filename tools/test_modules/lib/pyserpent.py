## serpent.py: pure Python implementation of the Serpent encryption algorithm.
## Originally by: Bjorn Edstrom <be@bjrn.se>, December 13, 2007.
## Updated by: Konstantin Vitkovskii <kon.vitkovskii@gmail.com>, 2026.
##
## Copyright Notice
## ================
##
## This code is derived from an implementation by Dr. Brian Gladman (gladman@seven77.demon.co.uk),
## which is subject to the following license:
##
## /* This is an independent implementation of the encryption algorithm:
##  *
##  * Serpent by Ross Anderson, Eli Biham, and Lars Knudsen
##  *
##  * which was a candidate algorithm in the Advanced Encryption Standard (AES)
##  * competition organized by the U.S. National Institute of Standards and Technology (NIST).
##  *
##  * Copyright in this implementation is held by Dr. B. R. Gladman,
##  * who hereby gives permission for its free direct or derivative use
##  * subject to acknowledgment of its origin and compliance with any conditions
##  * the algorithm's original authors may place on its usage.
##  *
##  * Dr. Brian Gladman, January 14, 1999
##  */
##
## This version has been adapted and updated for modern Python (3.x) compatibility by Konstantin Vitkovskii,
## a student at Omsk State Technical University (OmSTU), in 2026.
##
## The update includes syntax modernization, compatibility fixes for Python 3,
## implementation of PKCS#7 padding, and general code cleanup and testing.
##
## This file may be freely used, modified, and redistributed,
## provided that this copyright notice and attribution are preserved.

import struct
import sys
import os

block_size = 16
key_size = 32


class Serpent:

    def __init__(self, key:bytes=None):
        """Class for using Serpent algorithm"""

        if key:
            self.set_key(key)

    def set_key(self, key: bytes):
        """Init."""

        key_len = len(key)
        if key_len % 4:
            raise KeyError("key not a multiple of 4")
        if key_len > 32:
            raise KeyError("key_len > 32")

        self.key_context = [0] * 140

        key_word32 = [0] * 32
        i = 0
        while key:
            key_word32[i] = struct.unpack("<L", key[0:4])[0]
            key = key[4:]
            i += 1

        _set_key(self.key_context, key_word32, key_len)

    def decrypt(self, data: bytes):
        """Decrypt blocks."""

        if len(data) % 16:
            raise ValueError("block size must be a multiple of 16")

        plaintext = b''

        while data:
            a, b, c, d = struct.unpack("<4L", data[:16])
            temp = [a, b, c, d]
            _decrypt(self.key_context, temp)
            plaintext += struct.pack("<4L", *temp)
            data = data[16:]

        return plaintext

    def encrypt(self, data: bytes):
        """Encrypt blocks."""

        if len(data) % 16:
            raise ValueError("block size must be a multiple of 16")

        ciphertext = b''

        while data:
            a, b, c, d = struct.unpack("<4L", data[0:16])
            temp = [a, b, c, d]
            _encrypt(self.key_context, temp)
            ciphertext += struct.pack("<4L", *temp)
            data = data[16:]

        return ciphertext

    @staticmethod
    def pkcs7_pad(data: bytes, block_size: int = 16):
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def pkcs7_unpad(data: bytes):
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding length.")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Invalid PKCS#7 padding.")
        return data[:-pad_len]

    @staticmethod
    def generate_key(length: int = 32):
        if length not in (16, 24, 32):
            raise ValueError("Key length must be 16, 24, or 32 bytes.")
        return os.urandom(length)

    @staticmethod
    def generateIV():
        """
        Generate a secure 16-byte Initialization Vector (IV).
        Suitable for use in CBC mode.
        """
        return os.urandom(16)

    def get_name(self):
        """Return the name of the cipher."""

        return "Serpent"

    def get_block_size(self):
        """Get cipher block size in bytes."""

        return 16

    def get_key_size(self):
        """Get cipher key size in bytes."""

        return 32


#
# Below code needs for working Serpent algorithm.
#
#

WORD_BIGENDIAN = 0
if sys.byteorder == 'big':
    WORD_BIGENDIAN = 1


def _rotr32(x, n):
    return (x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)


def _rotl32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _byteswap32(x):
    return ((x & 0xff) << 24) | (((x >> 8) & 0xff) << 16) | \
           (((x >> 16) & 0xff) << 8) | ((x >> 24) & 0xff)
def inv_linear_transformation(x0, x1, x2, x3):
    x2 = _rotr32(x2, 22)
    x0 = _rotr32(x0, 5)
    x2 ^= x3 ^ ((x1 << 7) & 0xFFFFFFFF)
    x0 ^= x1 ^ x3
    x3 = _rotr32(x3, 7)
    x1 = _rotr32(x1, 1)
    x3 ^= x2 ^ ((x0 << 3) & 0xFFFFFFFF)
    x1 ^= x0 ^ x2
    x2 = _rotr32(x2, 3)
    x0 = _rotr32(x0, 13)
    return x0, x1, x2, x3

def _inbox0(a, b, c, d):
    t1 = (~a) % 0x100000000
    t2 = a ^ b
    t3 = t1 | t2
    t4 = d ^ t3
    t7 = d & t2
    t5 = c ^ t4
    t8 = t1 ^ t7
    g = t2 ^ t5
    t11 = a & t4
    t9 = g & t8
    t14 = t5 ^ t8
    f = t4 ^ t9
    t12 = t5 | f
    h = t11 ^ t12
    e = h ^ t14
    return e, f, g, h

def _inbox1(a, b, c, d):
    t1 = a ^ d
    t2 = a & b
    t3 = b ^ c
    t4 = a ^ t3
    t5 = b | d
    t7 = c | t1
    h = t4 ^ t5
    t8 = b ^ t7
    t11 = (~t2) % 0x100000000
    t9 = t4 & t8
    f = t1 ^ t9
    t13 = t9 ^ t11
    t12 = h & f
    g = t12 ^ t13
    t15 = a & d
    t16 = c ^ t13
    e = t15 ^ t16
    return e, f, g, h

def _inbox2(a, b, c, d):
    t1 = b ^ d
    t2 = (~t1) % 0x100000000
    t3 = a ^ c
    t4 = c ^ t1
    t7 = a | t2
    t5 = b & t4
    t8 = d ^ t7
    t11 = (~t4) % 0x100000000
    e = t3 ^ t5
    t9 = t3 | t8
    t14 = d & t11
    h = t1 ^ t9
    t12 = e | h
    f = t11 ^ t12
    t15 = t3 ^ t12
    g = t14 ^ t15
    return e, f, g, h

def _inbox3(a, b, c, d):
    t1 = b ^ c
    t2 = b | c
    t3 = a ^ c
    t7 = a ^ d
    t4 = t2 ^ t3
    t5 = d | t4
    t9 = t2 ^ t7
    e = t1 ^ t5
    t8 = t1 | t5
    t11 = a & t4
    g = t8 ^ t9
    t12 = e | t9
    f = t11 ^ t12
    t14 = a & g
    t15 = t2 ^ t14
    t16 = e & t15
    h = t4 ^ t16
    return e, f, g, h

def _inbox4(a, b, c, d):
    t1 = c ^ d
    t2 = c | d
    t3 = b ^ t2
    t4 = a & t3
    f = t1 ^ t4
    t6 = a ^ d
    t7 = b | d
    t8 = t6 & t7
    h = t3 ^ t8
    t10 = (~a) % 0x100000000
    t11 = c ^ h;
    t12 = t10 | t11
    e = t3 ^ t12;
    t14 = c | t4;
    t15 = t7 ^ t14;
    t16 = h | t10;
    g = t15 ^ t16
    return e, f, g, h

def _inbox5(a, b, c, d):
    t1 = (~c) % 0x100000000
    t2 = b & t1
    t3 = d ^ t2
    t4 = a & t3
    t5 = b ^ t1
    h = t4 ^ t5
    t7 = b | h
    t8 = a & t7
    f = t3 ^ t8
    t10 = a | d
    t11 = t1 ^ t7
    e = t10 ^ t11
    t13 = a ^ c
    t14 = b & t10
    t15 = t4 | t13
    g = t14 ^ t15
    return e, f, g, h

def _inbox6(a, b, c, d):
    t1 = (~a) % 0x100000000
    t2 = a ^ b
    t3 = c ^ t2
    t4 = c | t1
    t5 = d ^ t4
    t13 = d & t1
    f = t3 ^ t5
    t7 = t3 & t5
    t8 = t2 ^ t7
    t9 = b | t8
    h = t5 ^ t9
    t11 = b | h
    e = t8 ^ t11
    t14 = t3 ^ t11
    g = t13 ^ t14
    return e, f, g, h

def _inbox7(a, b, c, d):
    t1 = a & b
    t2 = a | b
    t3 = c | t1
    t4 = d & t2
    h = t3 ^ t4
    t6 = (~d) % 0x100000000
    t7 = b ^ t4
    t8 = h ^ t6
    t11 = c ^ t7
    t9 = t7 | t8
    f = a ^ t9
    t12 = d | f
    e = t11 ^ t12
    t14 = a & h
    t15 = t3 ^ f
    t16 = e ^ t14
    g = t15 ^ t16
    return e, f, g, h

inv_boxes = (_inbox0, _inbox1, _inbox2, _inbox3, _inbox4, _inbox5, _inbox6, _inbox7)



def _linear_transformation(x0, x1, x2, x3):
    x0 = _rotl32(x0, 13)
    x2 = _rotl32(x2, 3)
    x3 ^= x2 ^ ((x0 << 3) & 0xFFFFFFFF)
    x1 ^= x0 ^ x2
    x3 = _rotl32(x3, 7)
    x1 = _rotl32(x1, 1)
    x0 ^= x1 ^ x3
    x2 ^= x3 ^ ((x1 << 7) & 0xFFFFFFFF)
    x0 = _rotl32(x0, 5)
    x2 = _rotl32(x2, 22)
    return x0, x1, x2, x3

def _sbox0(a, b, c, d):
    t1 = a ^ d
    t2 = a & d
    t3 = c ^ t1
    t6 = b & t1
    t4 = b ^ t3
    t10 = t3 ^ 0xFFFFFFFF
    h = t2 ^ t4
    t7 = a ^ t6
    t14 = t7 ^ 0xFFFFFFFF
    t8 = c | t7
    t11 = t3 ^ t7
    g = t4 ^ t8
    t12 = h & t11
    f = t10 ^ t12
    e = t12 ^ t14
    return e, f, g, h

def _sbox1(a, b, c, d):
    t1 = (~a) % 0x100000000
    t2 = b ^ t1
    t3 = a | t2
    t4 = d | t2
    t5 = c ^ t3
    g = d ^ t5
    t7 = b ^ t4
    t8 = t2 ^ g
    t9 = t5 & t7
    h = t8 ^ t9
    t11 = t5 ^ t7
    f = h ^ t11
    t13 = t8 & t11
    e = t5 ^ t13
    return e, f, g, h

def _sbox2(a, b, c, d):
    t1 = (~a) % 0x100000000
    t2 = b ^ d
    t3 = c & t1
    t13 = d | t1
    e = t2 ^ t3
    t5 = c ^ t1
    t6 = c ^ e
    t7 = b & t6
    t10 = e | t5
    h = t5 ^ t7
    t9 = d | t7
    t11 = t9 & t10
    t14 = t2 ^ h
    g = a ^ t11
    t15 = g ^ t13
    f = t14 ^ t15
    return e, f, g, h

def _sbox3(a, b, c, d):
    t1 = a ^ c
    t2 = d ^ t1
    t3 = a & t2
    t4 = d ^ t3
    t5 = b & t4
    g = t2 ^ t5
    t7 = a | g
    t8 = b | d
    t11 = a | d
    t9 = t4 & t7
    f = t8 ^ t9
    t12 = b ^ t11
    t13 = g ^ t9
    t15 = t3 ^ t8
    h = t12 ^ t13
    t16 = c & t15
    e = t12 ^ t16
    return e, f, g, h

def _sbox4(a, b, c, d):
    t1 = a ^ d
    t2 = d & t1
    t3 = c ^ t2
    t4 = b | t3
    h = t1 ^ t4
    t6 = (~b) % 0x100000000
    t7 = t1 | t6
    e = t3 ^ t7
    t9 = a & e
    t10 = t1 ^ t6
    t11 = t4 & t10
    g = t9 ^ t11
    t13 = a ^ t3
    t14 = t10 & g
    f = t13 ^ t14
    return e, f, g, h

def _sbox5(a, b, c, d):
    t1 = (~a) % 0x100000000
    t2 = a ^ b
    t3 = a ^ d
    t4 = c ^ t1
    t5 = t2 | t3
    e = t4 ^ t5
    t7 = d & e
    t8 = t2 ^ e
    t10 = t1 | e
    f = t7 ^ t8
    t11 = t2 | t7
    t12 = t3 ^ t10
    t14 = b ^ t7
    g = t11 ^ t12
    t15 = f & t12
    h = t14 ^ t15
    return e, f, g, h

def _sbox6(a, b, c, d):
    t1 = (~a) % 0x100000000
    t2 = a ^ d
    t3 = b ^ t2
    t4 = t1 | t2
    t5 = c ^ t4
    f = b ^ t5
    t13 = (~t5) % 0x100000000
    t7 = t2 | f
    t8 = d ^ t7
    t9 = t5 & t8
    g = t3 ^ t9
    t11 = t5 ^ t8
    e = g ^ t11
    t14 = t3 & t11
    h = t13 ^ t14
    return e, f, g, h

def _sbox7(a, b, c, d):
    t1 = (~c) % 0x100000000
    t2 = b ^ c
    t3 = b | t1
    t4 = d ^ t3
    t5 = a & t4
    t7 = a ^ d
    h = t2 ^ t5
    t8 = b ^ t5
    t9 = t2 | t8
    t11 = d & t3
    f = t7 ^ t9
    t12 = t5 ^ f
    t15 = t1 | t4
    t13 = h & t12
    g = t11 ^ t13
    t16 = t12 ^ g
    e = t15 ^ t16
    return e, f, g, h

sboxes = (_sbox0, _sbox1, _sbox2, _sbox3, _sbox4, _sbox5, _sbox6, _sbox7)

def _set_key(l_key, key, key_len):
    key_len *= 8
    if key_len > 256:
        return False

    i = 0
    lk = (key_len + 31) / 32
    while i < lk:
        l_key[i] = key[i]
        if WORD_BIGENDIAN:
            l_key[i] = _byteswap32(key[i])
        i += 1

    if key_len < 256:
        while i < 8:
            l_key[i] = 0
            i += 1
        i = key_len // 32
        lk = 1 << (key_len % 32)
        l_key[i] = (l_key[i] & (lk - 1)) | lk
    for i in range(132):
        lk = l_key[i] ^ l_key[i + 3] ^ l_key[i + 5] ^ l_key[i + 7] ^ 0x9e3779b9 ^ i
        l_key[i + 8] = ((lk << 11) & 0xFFFFFFFF) | (lk >> 21)

    key = l_key

    for j in range(33):
        a, b, c, d = key[4*j+8], key[4*j+9], key[4*j+10], key[4*j+11]
        key[4*j+8], key[4*j+9], key[4*j+10], key[4*j+11] = sboxes[(3 - j) % 8](a, b, c, d)




def _encrypt(key_context, in_blk):
    a, b, c, d = in_blk[0], in_blk[1], in_blk[2], in_blk[3]

    if WORD_BIGENDIAN:
        a = _byteswap32(a)
        b = _byteswap32(b)
        c = _byteswap32(c)
        d = _byteswap32(d)

    for i in range(32):
        a ^= key_context[4 * i + 8]
        b ^= key_context[4 * i + 9]
        c ^= key_context[4 * i + 10]
        d ^= key_context[4 * i + 11]

        sbox_func = sboxes[i % 8]
        a, b, c, d = sbox_func(a, b, c, d)

        if i<31:
            a, b, c, d = _linear_transformation(a, b, c, d)

    a ^= key_context[4 * 32 + 8]
    b ^= key_context[4 * 32 + 9]
    c ^= key_context[4 * 32 + 10]
    d ^= key_context[4 * 32 + 11]

    if WORD_BIGENDIAN:
        a = _byteswap32(a)
        b = _byteswap32(b)
        c = _byteswap32(c)
        d = _byteswap32(d)

    in_blk[0] = a
    in_blk[1] = b
    in_blk[2] = c
    in_blk[3] = d

def _decrypt(key, in_blk):
    a = in_blk[0]
    b = in_blk[1]
    c = in_blk[2]
    d = in_blk[3]
    if WORD_BIGENDIAN:
        a = _byteswap32(a)
        b = _byteswap32(b)
        c = _byteswap32(c)
        d = _byteswap32(d)
    a ^= key[4 * 32 +  8]
    b ^= key[4 * 32 +  9]
    c ^= key[4 * 32 + 10]
    d ^= key[4 * 32 + 11]

    for i in range(31, -1, -1):
        if i<31:
            a, b, c, d = inv_linear_transformation(a, b, c, d)
        inbox_func = inv_boxes[i % 8]
        a, b, c, d = inbox_func(a, b, c, d)

        a ^= key[4 * i +  8]
        b ^= key[4 * i +  9]
        c ^= key[4 * i + 10]
        d ^= key[4 * i + 11]

    if WORD_BIGENDIAN:
        a = _byteswap32(a)
        b = _byteswap32(b)
        c = _byteswap32(c)
        d = _byteswap32(d)
    in_blk[0] = a
    in_blk[1] = b
    in_blk[2] = c
    in_blk[3] = d


def serpent_cbc_encrypt(key: bytes, data: bytes | str, iv = None) -> bytes:
    """
    Encrypt data using Serpent in CBC mode with PKCS#7 padding.

    :param key: encryption key (bytes)
    :param data: plaintext (bytes or str)
    :param iv: initialization vector (16 bytes)
    :return: iv + ciphertext (bytes)
    """

    if isinstance(data, str):
        data = data.encode('utf-8')

    data = Serpent.pkcs7_pad(data)
    out = b''
    _iv = Serpent.generateIV() if iv is None else iv
    last = _iv
    for i in range(len(data) // 16):
        temp = data[i * 16:(i + 1) * 16]
        to_encode = b''
        for j in range(4):
            temp1 = struct.unpack_from('<I', temp[j * 4:])[0]
            temp2 = struct.unpack_from('<I', last[j * 4:])[0]
            to_encode += struct.pack('<I', (temp1 ^ temp2) & 0xffffffff)
        last = Serpent(key).encrypt(to_encode)
        out += last
    return _iv + out


def serpent_cbc_decrypt(key: bytes, data: bytes) -> bytes:
    """
    Decrypt data using Serpent in CBC mode with PKCS#7 unpadding.

    :param key: encryption key (bytes)
    :param data: ciphertext (bytes)
    :return: plaintext (bytes)
    """

    out2 = b''
    last = data[:16]
    ciphertext = data[16:]
    for i in range(len(ciphertext) // 16):
        temp = Serpent(key).decrypt(ciphertext[i * 16:(i + 1) * 16])
        to_decode = b''
        for j in range(4):
            temp1 = struct.unpack_from('<I', temp[j * 4:])[0]
            temp2 = struct.unpack_from('<I', last[j * 4:])[0]
            to_decode += struct.pack('<I', (temp1 ^ temp2) & 0xffffffff)
        out2 += to_decode
        last = ciphertext[i * 16:(i + 1) * 16]
    return Serpent.pkcs7_unpad(out2)

if __name__ == "__main__":
    serpent = Serpent()
    key = b"0000000000000000"
    plaintext = "aaaeerggdddaswr1234"
    iv = b"\x00" * 16

    ciphertext = serpent_cbc_encrypt(key, plaintext, iv)
    decrypted = serpent_cbc_decrypt(key, ciphertext)

    print(ciphertext[16:].hex())
    print(decrypted.decode())
