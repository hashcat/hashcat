#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import os

try:
  import nacl.secret
  HAVE_NACL = True
except ImportError:
  HAVE_NACL = False

from lib.test_helpers import random_number

# SubWallet / polkadot-js keyring. The key is scrypt(password, salt, N/r/p, 32), the payload is a
# NaCl secretbox (XSalsa20-Poly1305) over the pkcs8 bytes. A crack is the Poly1305 tag matching,
# which is exact, not heuristic. The line carries the parameters, the salt, the nonce, the tag and
# the ciphertext: $subwallet$N,r,p$salt_b64$nonce_b64$tag_b64$ct_b64


# XSalsa20-Poly1305 (NaCl secretbox) without PyNaCl: pure-python fallback used
# when nacl is not installed. Same construction as the kernel verifies.

def _rotl32(v, c):
  return ((v << c) | (v >> (32 - c))) & 0xffffffff

def _salsa20_block(key, nonce8, counter):
  sigma = b"expand 32-byte k"
  key_w = [int.from_bytes(key[i*4:i*4+4],"little") for i in range(8)]
  nonce_w = [int.from_bytes(nonce8[i*4:i*4+4],"little") for i in range(2)]
  st = [int.from_bytes(sigma[0:4],"little"), key_w[0], key_w[1], key_w[2], key_w[3],
        int.from_bytes(sigma[4:8],"little"), nonce_w[0], nonce_w[1],
        counter & 0xffffffff, (counter >> 32) & 0xffffffff,
        int.from_bytes(sigma[8:12],"little"), key_w[4], key_w[5], key_w[6], key_w[7],
        int.from_bytes(sigma[12:16],"little")]
  x = st[:]
  for _ in range(10):
    # column rounds
    x[4] ^= _rotl32((x[0] + x[12]) & 0xffffffff, 7);  x[8] ^= _rotl32((x[4] + x[0]) & 0xffffffff, 9)
    x[12] ^= _rotl32((x[8] + x[4]) & 0xffffffff, 13); x[0] ^= _rotl32((x[12] + x[8]) & 0xffffffff, 18)
    x[9] ^= _rotl32((x[5] + x[1]) & 0xffffffff, 7);   x[13] ^= _rotl32((x[9] + x[5]) & 0xffffffff, 9)
    x[1] ^= _rotl32((x[13] + x[9]) & 0xffffffff, 13); x[5] ^= _rotl32((x[1] + x[13]) & 0xffffffff, 18)
    x[14] ^= _rotl32((x[10] + x[6]) & 0xffffffff, 7); x[2] ^= _rotl32((x[14] + x[10]) & 0xffffffff, 9)
    x[6] ^= _rotl32((x[2] + x[14]) & 0xffffffff, 13); x[10] ^= _rotl32((x[6] + x[2]) & 0xffffffff, 18)
    x[3] ^= _rotl32((x[15] + x[11]) & 0xffffffff, 7); x[7] ^= _rotl32((x[3] + x[15]) & 0xffffffff, 9)
    x[11] ^= _rotl32((x[7] + x[3]) & 0xffffffff, 13); x[15] ^= _rotl32((x[11] + x[7]) & 0xffffffff, 18)
    # row rounds
    x[1] ^= _rotl32((x[0] + x[3]) & 0xffffffff, 7);   x[2] ^= _rotl32((x[1] + x[0]) & 0xffffffff, 9)
    x[3] ^= _rotl32((x[2] + x[1]) & 0xffffffff, 13);  x[0] ^= _rotl32((x[3] + x[2]) & 0xffffffff, 18)
    x[6] ^= _rotl32((x[5] + x[4]) & 0xffffffff, 7);   x[7] ^= _rotl32((x[6] + x[5]) & 0xffffffff, 9)
    x[4] ^= _rotl32((x[7] + x[6]) & 0xffffffff, 13);  x[5] ^= _rotl32((x[4] + x[7]) & 0xffffffff, 18)
    x[11] ^= _rotl32((x[10] + x[9]) & 0xffffffff, 7); x[8] ^= _rotl32((x[11] + x[10]) & 0xffffffff, 9)
    x[9] ^= _rotl32((x[8] + x[11]) & 0xffffffff, 13); x[10] ^= _rotl32((x[9] + x[8]) & 0xffffffff, 18)
    x[12] ^= _rotl32((x[15] + x[14]) & 0xffffffff, 7);x[13] ^= _rotl32((x[12] + x[15]) & 0xffffffff, 9)
    x[14] ^= _rotl32((x[13] + x[12]) & 0xffffffff, 13);x[15] ^= _rotl32((x[14] + x[13]) & 0xffffffff, 18)
  return [(x[i] + st[i]) & 0xffffffff for i in range(16)]

def _hsalsa20(key, nonce16):
  # HSalsa20: key derivation for XSalsa20 (no final addition, fixed positions)
  sigma = b"expand 32-byte k"
  kw = [int.from_bytes(key[i*4:i*4+4],"little") for i in range(8)]
  nw = [int.from_bytes(nonce16[i*4:i*4+4],"little") for i in range(4)]
  st = [int.from_bytes(sigma[0:4],"little"), kw[0], kw[1], kw[2], kw[3],
        int.from_bytes(sigma[4:8],"little"), nw[0], nw[1], nw[2], nw[3],
        int.from_bytes(sigma[8:12],"little"), kw[4], kw[5], kw[6], kw[7],
        int.from_bytes(sigma[12:16],"little")]
  x = st[:]
  for _ in range(10):
    x[4] ^= _rotl32((x[0] + x[12]) & 0xffffffff, 7);  x[8] ^= _rotl32((x[4] + x[0]) & 0xffffffff, 9)
    x[12] ^= _rotl32((x[8] + x[4]) & 0xffffffff, 13); x[0] ^= _rotl32((x[12] + x[8]) & 0xffffffff, 18)
    x[9] ^= _rotl32((x[5] + x[1]) & 0xffffffff, 7);   x[13] ^= _rotl32((x[9] + x[5]) & 0xffffffff, 9)
    x[1] ^= _rotl32((x[13] + x[9]) & 0xffffffff, 13); x[5] ^= _rotl32((x[1] + x[13]) & 0xffffffff, 18)
    x[14] ^= _rotl32((x[10] + x[6]) & 0xffffffff, 7); x[2] ^= _rotl32((x[14] + x[10]) & 0xffffffff, 9)
    x[6] ^= _rotl32((x[2] + x[14]) & 0xffffffff, 13); x[10] ^= _rotl32((x[6] + x[2]) & 0xffffffff, 18)
    x[3] ^= _rotl32((x[15] + x[11]) & 0xffffffff, 7); x[7] ^= _rotl32((x[3] + x[15]) & 0xffffffff, 9)
    x[11] ^= _rotl32((x[7] + x[3]) & 0xffffffff, 13); x[15] ^= _rotl32((x[11] + x[7]) & 0xffffffff, 18)
    x[1] ^= _rotl32((x[0] + x[3]) & 0xffffffff, 7);   x[2] ^= _rotl32((x[1] + x[0]) & 0xffffffff, 9)
    x[3] ^= _rotl32((x[2] + x[1]) & 0xffffffff, 13);  x[0] ^= _rotl32((x[3] + x[2]) & 0xffffffff, 18)
    x[6] ^= _rotl32((x[5] + x[4]) & 0xffffffff, 7);   x[7] ^= _rotl32((x[6] + x[5]) & 0xffffffff, 9)
    x[4] ^= _rotl32((x[7] + x[6]) & 0xffffffff, 13);  x[5] ^= _rotl32((x[4] + x[7]) & 0xffffffff, 18)
    x[11] ^= _rotl32((x[10] + x[9]) & 0xffffffff, 7); x[8] ^= _rotl32((x[11] + x[10]) & 0xffffffff, 9)
    x[9] ^= _rotl32((x[8] + x[11]) & 0xffffffff, 13); x[10] ^= _rotl32((x[9] + x[8]) & 0xffffffff, 18)
    x[12] ^= _rotl32((x[15] + x[14]) & 0xffffffff, 7);x[13] ^= _rotl32((x[12] + x[15]) & 0xffffffff, 9)
    x[14] ^= _rotl32((x[13] + x[12]) & 0xffffffff, 13);x[15] ^= _rotl32((x[14] + x[13]) & 0xffffffff, 18)
  out_w = [x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]]
  return b"".join(w.to_bytes(4, "little") for w in out_w)

def _xsalsa20_stream(key, nonce24, n):
  sub = _hsalsa20(key, nonce24[:16])
  nonce8 = nonce24[16:]
  out = bytearray()
  ctr = 0
  while len(out) < n:
    blk = _salsa20_block(sub, nonce8, ctr)
    out += b"".join(w.to_bytes(4, "little") for w in blk)
    ctr += 1
  return bytes(out[:n])

def _poly1305_mac(msg, key32):
  r = int.from_bytes(key32[:16], "little")
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
  s = int.from_bytes(key32[16:], "little")
  p = (1 << 130) - 5
  acc = 0
  for i in range(0, len(msg), 16):
    blk = msg[i:i+16]
    n = int.from_bytes(blk, "little") + (1 << (8 * len(blk)))
    acc = ((acc + n) * r) % p
  return ((acc + s) & 0xffffffffffffffffffffffffffffffff).to_bytes(16, "little")

def _seal(key, nonce, pt):
  stream = _xsalsa20_stream(key, nonce, 32 + len(pt))
  poly_key = stream[:32]
  ct = bytes(a ^ b for a, b in zip(pt, stream[32:]))
  tag = _poly1305_mac(ct, poly_key)
  return tag + ct

def _open(key, nonce, box):
  tag, ct = box[:16], box[16:]
  stream = _xsalsa20_stream(key, nonce, 32 + len(ct))
  if _poly1305_mac(ct, stream[:32]) != tag:
    raise ValueError("bad tag")
  return bytes(a ^ b for a, b in zip(ct, stream[32:]))


SCRYPT_N = 131072
SCRYPT_R = 8
SCRYPT_P = 1


def _make_hash(word, salt, pt_len):
  if isinstance(word, str):
    word = word.encode()

  nonce = os.urandom(24)

  key = hashlib.scrypt(word, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32,
                       maxmem=256 * 1024 * 1024)

  ct = _seal(key, nonce, os.urandom(pt_len))  # tag(16) || ct

  return "$subwallet$%d,%d,%d$%s$%s$%s$%s" % (
    SCRYPT_N, SCRYPT_R, SCRYPT_P,
    base64.b64encode(salt).decode(),
    base64.b64encode(nonce).decode(),
    base64.b64encode(ct[:16]).decode(),
    base64.b64encode(ct[16:]).decode())


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


def module_generate_hash(word, salt=None):
  if salt is None:
    salt = os.urandom(32)

  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if len(salt) != 32:
    salt = os.urandom(32)

  return _make_hash(word, salt, random_number(8, 128))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if not hash_in.startswith("$subwallet$"):
    return None

  fields = hash_in.split("$")

  if len(fields) != 7:
    return None

  try:
    n, r, p = (int(v) for v in fields[2].split(","))
    salt  = base64.b64decode(fields[3])
    nonce = base64.b64decode(fields[4])
    tag   = base64.b64decode(fields[5])
    ct    = base64.b64decode(fields[6])
  except Exception:
    return None

  try:
    key = hashlib.scrypt(word, salt=salt, n=n, r=r, p=p, dklen=32,
                         maxmem=256 * 1024 * 1024)

    _open(key, nonce, tag + ct)
  except Exception:
    return None

  return (hash_in, word)
