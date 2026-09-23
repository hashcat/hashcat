#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import re

from cryptography.hazmat.primitives.asymmetric import ec

# Raw secp256k1 private key (64 hex chars) -> P2SH(P2WPKH) "compat" address (3...), uncompressed
# public key.

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _sha256(b):
  return hashlib.sha256(b).digest()


def _hash160(b):
  h = hashlib.new("ripemd160")
  h.update(_sha256(b))
  return h.digest()


def _b58enc(b):
  n = int.from_bytes(b, "big")
  s = ""

  while n > 0:
    n, r = divmod(n, 58)
    s = B58[r] + s

  for c in b:
    if c == 0:
      s = "1" + s
    else:
      break

  return s


def _b58dec(s):
  n = 0

  for c in s:
    n = n * 58 + B58.index(c)

  full = n.to_bytes((n.bit_length() + 7) // 8, "big")
  pad = 0

  for c in s:
    if c == "1":
      pad += 1
    else:
      break

  return b"\x00" * pad + full


def _b58check_enc(b):
  return _b58enc(b + _sha256(_sha256(b))[:4])


def _b58check_dec(s):
  raw = _b58dec(s)
  data, chk = raw[:-4], raw[-4:]

  if _sha256(_sha256(data))[:4] != chk:
    raise ValueError("bad checksum")

  return data


def _pub_ser(k, compressed):
  nums = ec.derive_private_key(k, ec.SECP256K1()).public_key().public_numbers()
  x = nums.x.to_bytes(32, "big")

  if compressed:
    return (b"\x03" if nums.y & 1 else b"\x02") + x

  return b"\x04" + x + nums.y.to_bytes(32, "big")


def _compat_addr(pub):
  # P2SH wrapping a P2WPKH redeem script: OP_0 PUSH(20) hash160 (pub), version byte 0x05.

  redeem = b"\x00\x14" + _hash160(pub)

  return _b58check_enc(b"\x05" + _hash160(redeem))


def _bip32_seed_key(seed):
  # BIP32 master key from seed, then hardened child m/0', matching Bitcoin::Crypto from_seed +
  # derive_key ("m/0'").

  master = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
  k_par = int.from_bytes(master[:32], "big")
  cc = master[32:]

  data = b"\x00" + k_par.to_bytes(32, "big") + (0 | 0x80000000).to_bytes(4, "big")
  child = hmac.new(cc, data, hashlib.sha512).digest()

  return (int.from_bytes(child[:32], "big") + k_par) % N


def module_constraints():
  return [[64, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_get_random_password(word):
  seed = word if isinstance(word, bytes) else word.encode("latin-1")
  k = _bip32_seed_key(seed)

  return ("%064x" % k).encode()


def module_generate_hash(word, salt=None, iterations=None):
  if isinstance(word, bytes):
    word = word.decode("latin-1")

  if not re.match(r"^[0-9a-fA-F]{64}$", word):
    return None

  k = int(word, 16)

  if not 1 <= k < N:
    return None

  return _compat_addr(_pub_ser(k, False))


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_str = line[:idx].decode("latin-1")
  word = line[idx + 1:]

  if not re.match(rb"^[0-9a-fA-F]{64}$", word):
    return None

  try:
    _b58check_dec(hash_str)
  except Exception:
    return None

  return (module_generate_hash(word), word)
