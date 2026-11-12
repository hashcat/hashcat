#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Monero wallet: password -> cn_slow_hash (CryptoNight v0, 2 MiB scratchpad, 2^19 two-step
# main-loop iterations) -> 32-byte chacha key -> chacha20 (chacha8 for ancient wallets)
# decrypt of the blob at offset 10; the password is right if "key_data" or
# "m_creation_timestamp" shows up in the first 32 plaintext bytes (same check as JtR
# monero_fmt_plug.c). The AES work uses the same big-endian-word T-table form as the
# kernel (validated against monero's aesb.c); the extra hash comes from the lib modules,
# where skein256 is Skein-512 with a 256-bit digest, which is what monero's skein.c does.

import base64

from lib.test_helpers import split_hash_word
from lib.blake import blake256
from lib.groestl import groestl256
from lib.jh import jh256
from lib.skein import skein256

MEMORY = 1 << 21
ITER = 1 << 20
TOTALBLOCKS = MEMORY // 16

M32 = (1 << 32) - 1
M64 = (1 << 64) - 1

# ---------------- keccak (keccak.c / hash.c) ----------------

KECCAKF_RNDC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
KECCAKF_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
KECCAKF_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]

def _rol64(x, n):
    return ((x << n) | (x >> (64 - n))) & M64

def keccak_f1600(st):
    for rnd in range(24):
        bc = [st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20] for i in range(5)]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ _rol64(bc[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                st[j + i] ^= t
        t = st[1]
        for i in range(24):
            j = KECCAKF_PILN[i]
            bc0 = st[j]
            st[j] = _rol64(t, KECCAKF_ROTC[i])
            t = bc0
        for j in range(0, 25, 5):
            row = st[j:j+5]
            for i in range(5):
                st[j + i] = row[i] ^ ((~row[(i + 1) % 5] & M64) & row[(i + 2) % 5])
        st[0] ^= KECCAKF_RNDC[rnd]

def keccak1600(data: bytes) -> bytes:
    """monero keccak1600(): rate 136, pad 0x01 ... 0x80, permutation on the final block too"""
    st = [0] * 25
    off = 0
    while len(data) - off >= 136:
        blk = data[off:off + 136]
        for i in range(17):
            st[i] ^= int.from_bytes(blk[8*i:8*i+8], 'little')
        keccak_f1600(st)
        off += 136
    tmp = bytearray(136)
    left = len(data) - off
    tmp[:left] = data[off:]
    tmp[left] ^= 0x01
    tmp[135] ^= 0x80
    for i in range(17):
        st[i] ^= int.from_bytes(tmp[8*i:8*i+8], 'little')
    keccak_f1600(st)
    return b''.join(x.to_bytes(8, 'little') for x in st)

# ---------------- AES T-tables (same big-endian-word form as the kernel) ----------------

def _rol8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF

def _make_sbox():
    p = 1
    q = 1
    sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        xformed = q ^ _rol8(q, 1) ^ _rol8(q, 2) ^ _rol8(q, 3) ^ _rol8(q, 4)
        sbox[p] = (xformed ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox

SBOX = _make_sbox()
MUL2 = [((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF for x in range(256)]
MUL3 = [MUL2[x] ^ x for x in range(256)]

TE0 = [0] * 256
TE1 = [0] * 256
TE2 = [0] * 256
TE3 = [0] * 256

for _x in range(256):
    _s = SBOX[_x]
    TE0[_x] = (MUL2[_s] << 24) | (_s << 16) | (_s << 8) | MUL3[_s]
    TE1[_x] = ((TE0[_x] >> 8) | (TE0[_x] << 24)) & M32
    TE2[_x] = ((TE1[_x] >> 8) | (TE1[_x] << 24)) & M32
    TE3[_x] = ((TE2[_x] >> 8) | (TE2[_x] << 24)) & M32

def _bswap32(x):
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | ((x >> 24) & 0xFF)

def aes256_expand(key: bytes):
    """FIPS-197 AES-256 key schedule, 240 bytes"""
    w = [list(key[4*i:4*i+4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i-1])
        if i % 8 == 0:
            t = [SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
            t[0] ^= rcon
            rcon = MUL2[rcon]
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i-8][j] ^ t[j] for j in range(4)])
    return bytes(b for word in w for b in word)

def _ks_be_words(exp: bytes):
    return [int.from_bytes(exp[4*i:4*i+4], 'big') for i in range(60)]

def _pseudo_round_words(t, o, ks):
    """aesb_pseudo_round on the 4 LE words t[o..o+3]: 10 rounds, no initial AddRoundKey"""
    x0 = _bswap32(t[o]); x1 = _bswap32(t[o+1]); x2 = _bswap32(t[o+2]); x3 = _bswap32(t[o+3])
    for r in range(10):
        k = 4 * r
        y0 = TE0[x0 >> 24] ^ TE1[(x1 >> 16) & 0xFF] ^ TE2[(x2 >> 8) & 0xFF] ^ TE3[x3 & 0xFF] ^ ks[k]
        y1 = TE0[x1 >> 24] ^ TE1[(x2 >> 16) & 0xFF] ^ TE2[(x3 >> 8) & 0xFF] ^ TE3[x0 & 0xFF] ^ ks[k+1]
        y2 = TE0[x2 >> 24] ^ TE1[(x3 >> 16) & 0xFF] ^ TE2[(x0 >> 8) & 0xFF] ^ TE3[x1 & 0xFF] ^ ks[k+2]
        y3 = TE0[x3 >> 24] ^ TE1[(x0 >> 16) & 0xFF] ^ TE2[(x1 >> 8) & 0xFF] ^ TE3[x2 & 0xFF] ^ ks[k+3]
        x0, x1, x2, x3 = y0, y1, y2, y3
    t[o] = _bswap32(x0); t[o+1] = _bswap32(x1); t[o+2] = _bswap32(x2); t[o+3] = _bswap32(x3)

def _single_round_words(blk, key):
    """aesb_single_round on 4 LE words with a 16-byte key block (4 LE words)"""
    x0 = _bswap32(blk[0]); x1 = _bswap32(blk[1]); x2 = _bswap32(blk[2]); x3 = _bswap32(blk[3])
    k0 = _bswap32(key[0]); k1 = _bswap32(key[1]); k2 = _bswap32(key[2]); k3 = _bswap32(key[3])
    y0 = TE0[x0 >> 24] ^ TE1[(x1 >> 16) & 0xFF] ^ TE2[(x2 >> 8) & 0xFF] ^ TE3[x3 & 0xFF] ^ k0
    y1 = TE0[x1 >> 24] ^ TE1[(x2 >> 16) & 0xFF] ^ TE2[(x3 >> 8) & 0xFF] ^ TE3[x0 & 0xFF] ^ k1
    y2 = TE0[x2 >> 24] ^ TE1[(x3 >> 16) & 0xFF] ^ TE2[(x0 >> 8) & 0xFF] ^ TE3[x1 & 0xFF] ^ k2
    y3 = TE0[x3 >> 24] ^ TE1[(x0 >> 16) & 0xFF] ^ TE2[(x1 >> 8) & 0xFF] ^ TE3[x2 & 0xFF] ^ k3
    return [_bswap32(y0), _bswap32(y1), _bswap32(y2), _bswap32(y3)]

# ---------------- cn_slow_hash (slow-hash.c portable path, variant 0) ----------------

def cn_slow_hash(data: bytes) -> bytes:
    state = bytearray(keccak1600(data))          # 200 bytes

    st32 = [int.from_bytes(state[4*i:4*i+4], 'little') for i in range(50)]

    # scratchpad fill: key = state[0:32], text = state[64:192]

    ks1 = _ks_be_words(aes256_expand(bytes(state[0:32])))

    text = list(st32[16:48])

    ls = [0] * (MEMORY // 4)

    for chunk in range(MEMORY // 128):
        for j in range(8):
            _pseudo_round_words(text, 4 * j, ks1)
        ls[32*chunk:32*chunk+32] = text

    # a = state[0:16] ^ state[32:48]; b = state[16:32] ^ state[48:64]

    a = [st32[i] ^ st32[i + 8] for i in range(4)]
    b = [st32[i + 4] ^ st32[i + 12] for i in range(4)]

    for _ in range(ITER // 2):
        # iteration 1

        a64_0 = a[0] | (a[1] << 32)
        a64_1 = a[2] | (a[3] << 32)

        j = ((a64_0 >> 4) & (TOTALBLOCKS - 1)) * 4

        c1 = _single_round_words(ls[j:j+4], a)

        ls[j]   = c1[0] ^ b[0]
        ls[j+1] = c1[1] ^ b[1]
        ls[j+2] = c1[2] ^ b[2]
        ls[j+3] = c1[3] ^ b[3]

        # iteration 2

        c164 = c1[0] | (c1[1] << 32)

        j = ((c164 >> 4) & (TOTALBLOCKS - 1)) * 4

        c2 = ls[j:j+4]

        prod = c164 * (c2[0] | (c2[1] << 32))

        na0 = (a64_0 + (prod >> 64)) & M64
        na1 = (a64_1 + (prod & M64)) & M64

        ls[j]   = na0 & M32
        ls[j+1] = na0 >> 32
        ls[j+2] = na1 & M32
        ls[j+3] = na1 >> 32

        a = [c2[0] ^ ls[j], c2[1] ^ ls[j+1], c2[2] ^ ls[j+2], c2[3] ^ ls[j+3]]
        b = c1

    # reassembly: key = state[32:64], text = state[64:192] (original)

    ks2 = _ks_be_words(aes256_expand(bytes(state[32:64])))

    text = list(st32[16:48])

    for chunk in range(MEMORY // 128):
        for j in range(8):
            text[4*j]   ^= ls[32*chunk + 4*j]
            text[4*j+1] ^= ls[32*chunk + 4*j + 1]
            text[4*j+2] ^= ls[32*chunk + 4*j + 2]
            text[4*j+3] ^= ls[32*chunk + 4*j + 3]
            _pseudo_round_words(text, 4 * j, ks2)

    for i in range(32):
        st32[16 + i] = text[i]

    # hash_permutation + extra hash

    st64 = [st32[2*i] | (st32[2*i+1] << 32) for i in range(25)]

    keccak_f1600(st64)

    final = b''.join(x.to_bytes(8, 'little') for x in st64)

    return (blake256, groestl256, jh256, skein256)[final[0] & 3](final)

# ---------------- chacha (chacha.c, DJB) ----------------

def _rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & M32

def chacha_crypt(rounds: int, data: bytes, key: bytes, iv: bytes) -> bytes:
    j = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    j += [int.from_bytes(key[i:i+4], 'little') for i in range(0, 32, 4)]
    j += [0, 0]
    j += [int.from_bytes(iv[i:i+4], 'little') for i in range(0, 8, 4)]
    out = bytearray()
    pos = 0
    while pos < len(data):
        x = list(j)
        for _ in range(rounds // 2):
            # column rounds
            x[0] = (x[0] + x[4]) & M32;  x[12] = _rol32(x[12] ^ x[0], 16)
            x[8] = (x[8] + x[12]) & M32; x[4]  = _rol32(x[4] ^ x[8], 12)
            x[0] = (x[0] + x[4]) & M32;  x[12] = _rol32(x[12] ^ x[0], 8)
            x[8] = (x[8] + x[12]) & M32; x[4]  = _rol32(x[4] ^ x[8], 7)
            x[1] = (x[1] + x[5]) & M32;  x[13] = _rol32(x[13] ^ x[1], 16)
            x[9] = (x[9] + x[13]) & M32; x[5]  = _rol32(x[5] ^ x[9], 12)
            x[1] = (x[1] + x[5]) & M32;  x[13] = _rol32(x[13] ^ x[1], 8)
            x[9] = (x[9] + x[13]) & M32; x[5]  = _rol32(x[5] ^ x[9], 7)
            x[2] = (x[2] + x[6]) & M32;  x[14] = _rol32(x[14] ^ x[2], 16)
            x[10] = (x[10] + x[14]) & M32; x[6] = _rol32(x[6] ^ x[10], 12)
            x[2] = (x[2] + x[6]) & M32;  x[14] = _rol32(x[14] ^ x[2], 8)
            x[10] = (x[10] + x[14]) & M32; x[6] = _rol32(x[6] ^ x[10], 7)
            x[3] = (x[3] + x[7]) & M32;  x[15] = _rol32(x[15] ^ x[3], 16)
            x[11] = (x[11] + x[15]) & M32; x[7] = _rol32(x[7] ^ x[11], 12)
            x[3] = (x[3] + x[7]) & M32;  x[15] = _rol32(x[15] ^ x[3], 8)
            x[11] = (x[11] + x[15]) & M32; x[7] = _rol32(x[7] ^ x[11], 7)
            # diagonal rounds
            x[0] = (x[0] + x[5]) & M32;  x[15] = _rol32(x[15] ^ x[0], 16)
            x[10] = (x[10] + x[15]) & M32; x[5] = _rol32(x[5] ^ x[10], 12)
            x[0] = (x[0] + x[5]) & M32;  x[15] = _rol32(x[15] ^ x[0], 8)
            x[10] = (x[10] + x[15]) & M32; x[5] = _rol32(x[5] ^ x[10], 7)
            x[1] = (x[1] + x[6]) & M32;  x[12] = _rol32(x[12] ^ x[1], 16)
            x[11] = (x[11] + x[12]) & M32; x[6] = _rol32(x[6] ^ x[11], 12)
            x[1] = (x[1] + x[6]) & M32;  x[12] = _rol32(x[12] ^ x[1], 8)
            x[11] = (x[11] + x[12]) & M32; x[6] = _rol32(x[6] ^ x[11], 7)
            x[2] = (x[2] + x[7]) & M32;  x[13] = _rol32(x[13] ^ x[2], 16)
            x[8] = (x[8] + x[13]) & M32; x[7]  = _rol32(x[7] ^ x[8], 12)
            x[2] = (x[2] + x[7]) & M32;  x[13] = _rol32(x[13] ^ x[2], 8)
            x[8] = (x[8] + x[13]) & M32; x[7]  = _rol32(x[7] ^ x[8], 7)
            x[3] = (x[3] + x[4]) & M32;  x[14] = _rol32(x[14] ^ x[3], 16)
            x[9] = (x[9] + x[14]) & M32; x[4]  = _rol32(x[4] ^ x[9], 12)
            x[3] = (x[3] + x[4]) & M32;  x[14] = _rol32(x[14] ^ x[3], 8)
            x[9] = (x[9] + x[14]) & M32; x[4]  = _rol32(x[4] ^ x[9], 7)
        ks = b''.join(((x[i] + j[i]) & M32).to_bytes(4, 'little') for i in range(16))
        blk = data[pos:pos+64]
        out += bytes(m ^ k for m, k in zip(blk, ks))
        pos += 64
        j[12] = (j[12] + 1) & M32
        if j[12] == 0:
            j[13] = (j[13] + 1) & M32
    return bytes(out)

# ---------------- hashcat test module interface ----------------

def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [32, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
  }

def module_generate_hash(word, salt, sign=None):
  salt_bin = bytes.fromhex(salt)

  iv  = salt_bin[0:8]
  rnd = salt_bin[8:16]

  key = cn_slow_hash(word)

  # half of the vectors get chacha8 and the binary-format marker, as in pre-2017 wallets;
  # "key_data" / "m_creation_timestamp" land inside the 32 plaintext bytes the verify checks

  if rnd[0] & 1:
    rounds = 8
    pt = b'\x01\x11\x01\x01\x01\x01\x02\x01\x01\x08\x14m_creation_timestamp\x05' + rnd
  else:
    rounds = 20
    pt = b'{"version":1,"key_data":"' + base64.b64encode(rnd) + b'","watch_only":0}'

  ct = chacha_crypt(rounds, pt, key, iv)

  blob = iv + b"\x00\x00" + ct

  return "$monero$0*" + blob.hex()

def module_verify_hash(line):
  res = split_hash_word(line)

  if res is None:
    return None

  hash_str, word = res

  if not hash_str.startswith("$monero$"):
    return None

  data = hash_str[8:].split("*")

  if len(data) != 2:
    return None

  try:
    blob = bytes.fromhex(data[1])
  except ValueError:
    return None

  if len(blob) < 42:
    return None

  iv = blob[0:8]
  ct = blob[10:]

  key = cn_slow_hash(word)

  for rounds in (20, 8):
    pt = chacha_crypt(rounds, ct, key, iv)

    if b"key_data" in pt[:32] or b"m_creation_timestamp" in pt[:32]:
      return (hash_str, word)

  return None
