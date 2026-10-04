#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

# Bitcoin WIF, compressed P2PKH. The password is a WIF private key; the hash is the legacy address
# derived from it. The random password is a BIP32 key at m/0' off a seed, exported as compressed WIF.

SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def module_constraints():
  return [[52, 52], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def _double_sha256(data):
  return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _base58_encode(data):
  num = int.from_bytes(data, "big")

  out = ""

  while num > 0:
    num, rem = divmod(num, 58)
    out = B58_ALPHABET[rem] + out

  pad = 0

  for byte in data:
    if byte == 0:
      pad += 1
    else:
      break

  return "1" * pad + out


def _base58_decode(text):
  num = 0

  for char in text:
    idx = B58_ALPHABET.find(char)

    if idx < 0:
      return None

    num = num * 58 + idx

  body = num.to_bytes((num.bit_length() + 7) // 8, "big")

  pad = len(text) - len(text.lstrip("1"))

  return b"\x00" * pad + body


def _base58check_encode(payload):
  return _base58_encode(payload + _double_sha256(payload)[:4])


def _base58check_decode(text):
  # perl's decode_base58check, returning the payload without its 4 byte checksum, or None when the
  # string is not valid base58check

  raw = _base58_decode(text)

  if raw is None or len(raw) < 5:
    return None

  payload, checksum = raw[:-4], raw[-4:]

  if _double_sha256(payload)[:4] != checksum:
    return None

  return payload


def _wif_from_private(priv32, compressed):
  payload = b"\x80" + priv32 + (b"\x01" if compressed else b"")

  return _base58check_encode(payload)


def _private_from_wif(wif):
  # returns (priv32, compressed) for a valid mainnet WIF, else None

  payload = _base58check_decode(wif)

  if payload is None:
    return None

  if payload[0] != 0x80:
    return None

  if len(payload) == 34 and payload[33] == 0x01:
    return payload[1:33], True

  if len(payload) == 33:
    return payload[1:33], False

  return None


def _public_key(priv_int, compressed):
  key = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())

  numbers = key.public_key().public_numbers()

  x = numbers.x.to_bytes(32, "big")

  if compressed:
    return (b"\x02" if (numbers.y & 1) == 0 else b"\x03") + x

  return b"\x04" + x + numbers.y.to_bytes(32, "big")


def _legacy_address(pub):
  h = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()

  return _base58check_encode(b"\x00" + h)


def _bip32_from_seed(seed):
  data = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()

  return int.from_bytes(data[:32], "big"), data[32:]


def _bip32_derive_hardened(key, chain_code, index):
  data = b"\x00" + key.to_bytes(32, "big") + (0x80000000 + index).to_bytes(4, "big")

  block = hmac.new(chain_code, data, hashlib.sha512).digest()

  child = (int.from_bytes(block[:32], "big") + key) % SECP256K1_ORDER

  return child, block[32:]


def module_get_random_password(word):
  # BIP32 master from the seed, then the m/0' child, exported as a compressed WIF

  key, chain_code = _bip32_from_seed(word)
  key, chain_code = _bip32_derive_hardened(key, chain_code, 0)

  return _wif_from_private(key.to_bytes(32, "big"), True).encode("ascii")


def module_generate_hash(word, salt=None, iterations=None):
  try:
    wif = word.decode("ascii")
  except UnicodeDecodeError:
    return None

  if _base58check_decode(wif) is None:
    return None

  parsed = _private_from_wif(wif)

  if parsed is None:
    return None

  priv32, compressed = parsed

  if compressed is not True:
    return None

  return _legacy_address(_public_key(int.from_bytes(priv32, "big"), compressed))


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx]
  word = line[idx + 1:]

  try:
    hash_str = hash_in.decode("ascii")
    word_str = word.decode("ascii")
  except UnicodeDecodeError:
    return None

  if _base58check_decode(hash_str) is None or _base58check_decode(word_str) is None:
    return None

  if len(word_str) != 52:
    return None

  if word_str[0] not in ("K", "L"):
    return None

  return (module_generate_hash(word), word)
