#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import re

from cryptography.hazmat.primitives.asymmetric import ec

# Raw secp256k1 private key (64 hex chars) -> P2WPKH bech32 (segwit) address, uncompressed public
# key. get_segwit_address refuses an uncompressed key because such a P2WPKH output cannot be spent,
# so the perl builds the address straight from the witness program: hash160 of the uncompressed
# public key. This mode is for finding the key behind an address somebody already made that way.

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _sha256(b):
  return hashlib.sha256(b).digest()


def _hash160(b):
  h = hashlib.new("ripemd160")
  h.update(_sha256(b))
  return h.digest()


def _pub_ser(k, compressed):
  nums = ec.derive_private_key(k, ec.SECP256K1()).public_key().public_numbers()
  x = nums.x.to_bytes(32, "big")

  if compressed:
    return (b"\x03" if nums.y & 1 else b"\x02") + x

  return b"\x04" + x + nums.y.to_bytes(32, "big")


def _convertbits(data):
  acc = 0
  bits = 0
  ret = []

  for b in data:
    acc = (acc << 8) | b
    bits += 8

    while bits >= 5:
      bits -= 5
      ret.append((acc >> bits) & 31)

  if bits:
    ret.append((acc << (5 - bits)) & 31)

  return ret


def _bech32_polymod(values):
  gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  chk = 1

  for v in values:
    top = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v

    for i in range(5):
      chk ^= gen[i] if ((top >> i) & 1) else 0

  return chk


def _segwit_addr(pub, hrp="bc", witver=0):
  data = [witver] + _convertbits(_hash160(pub))
  values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data
  polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
  data += [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

  return hrp + "1" + "".join(BECH32[d] for d in data)


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

  return _segwit_addr(_pub_ser(k, False))


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_str = line[:idx].decode("latin-1")
  word = line[idx + 1:]

  if not re.match(rb"^[0-9a-fA-F]{64}$", word):
    return None

  if not re.match(r"^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]*$", hash_str):
    return None

  return (module_generate_hash(word), word)
