#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Pure python GOST R 34.11-94 (RFC 5831) with the test parameter S-box
# (id-GostR3411-94-TestParamSet), the variant hash-mode 6900 uses and the one
# perl's Digest::GOST produces. Written from the standard so the suite needs no
# binding and no git-fetched package for this single oracle, the same reason
# lib/pyserpent.py and lib/pytwofish.py are here rather than a dependency.
#
# The constants below (the S-box, the C3 mixing constant, the byte permutation)
# are the standard's own public values. The output was checked against the
# RFC 5831 test vectors, e.g. the empty string is
# ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d and "abc" is
# f3134348c44fb1b2a277729e2285ebb5cb5e0f29c975bc753b70497c06a4d51d.

MASK32 = 0xFFFFFFFF

# id-GostR3411-94-TestParamSet S-box (RFC 4357).
SBOX = (
    (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
    (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
    (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
    (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
    (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
    (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
    (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
    (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
)

# GOST 28147-89 round key order: K0..K7 three times, then K7..K0.
SEQ = tuple(range(8)) * 3 + tuple(range(7, -1, -1))

# The one non-zero step constant, C3 (RFC 5831); C2 and C4 are zero.
C3 = bytes.fromhex("ff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00")


def _t(word):
    # The 8 by 4-bit S-box substitution of a 32-bit word.
    out = 0

    for i in range(8):
        out |= SBOX[i][(word >> (4 * i)) & 0xF] << (4 * i)

    return out


def _round(n, subkey):
    n = _t((n + subkey) & MASK32)

    return ((n << 11) | (n >> 21)) & MASK32


def _gost_encrypt(block8, key32):
    # GOST 28147-89 on one 64-bit block under a 256-bit key.
    subkeys = [int.from_bytes(key32[i * 4:i * 4 + 4], "little") for i in range(8)]

    n1 = int.from_bytes(block8[0:4], "little")
    n2 = int.from_bytes(block8[4:8], "little")

    for i in SEQ:
        n1, n2 = _round(n1, subkeys[i]) ^ n2, n1

    return n2.to_bytes(4, "little") + n1.to_bytes(4, "little")


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _a(x):
    # A: (x1 xor x2) . x4 . x3 . x2, over 64-bit words x = x4.x3.x2.x1.
    x4, x3, x2, x1 = x[0:8], x[8:16], x[16:24], x[24:32]

    return _xor(x1, x2) + x4 + x3 + x2


def _p(x):
    # P: byte permutation phi (RFC 5831), out[i] = x[(i % 4) * 8 + i // 4].
    return bytes(x[(i % 4) * 8 + (i // 4)] for i in range(32))


def _psi(y):
    # Psi: the message LFSR. Sixteen big-endian 16-bit words y16(=y[0:2])..y1(=y[30:32]);
    # the new top word is y1 xor y2 xor y3 xor y4 xor y13 xor y16, the rest shift up.
    lo = y[30] ^ y[28] ^ y[26] ^ y[24] ^ y[6] ^ y[0]
    hi = y[31] ^ y[29] ^ y[27] ^ y[25] ^ y[7] ^ y[1]

    return bytes((lo, hi)) + y[0:30]


def _psi_n(y, n):
    for _ in range(n):
        y = _psi(y)

    return y


def _step(h, m):
    # The step (compression) function, H_out = f(H_in, m).
    u, v = h, m
    keys = []

    for c in (None, bytes(32), C3, bytes(32)):
        if c is not None:
            u = _xor(_a(u), c)
            v = _a(_a(v))

        keys.append(_p(_xor(u, v)))

    # Encipher the four 64-bit words of H, big-endian, under K1..K4.
    s = b""

    for j in range(4):
        hj = h[24 - 8 * j:32 - 8 * j][::-1]
        s = _gost_encrypt(hj, keys[j][::-1])[::-1] + s

    # H_out = psi^61(H xor psi(m xor psi^12(S))).
    x = _psi_n(s, 12)
    x = _xor(x, m)
    x = _psi(x)
    x = _xor(h, x)

    return _psi_n(x, 61)


def _digest(data):
    h = bytes(32)
    checksum = 0
    bits = 0

    for i in range(0, len(data), 32):
        part = data[i:i + 32][::-1]
        bits += len(part) * 8
        checksum = (checksum + int.from_bytes(part, "big")) % (1 << 256)

        if len(part) < 32:
            part = bytes(32 - len(part)) + part

        h = _step(h, part)

    h = _step(h, bits.to_bytes(32, "big"))
    h = _step(h, checksum.to_bytes(32, "big"))

    return h[::-1]


def hexdigest(data):
    return _digest(data).hex()
