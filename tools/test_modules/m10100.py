#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# SipHash-2-4, keyed with the 16 byte salt. hashcat prints the two 32 bit halves byte swapped.

MASK = 0xffffffffffffffff


def _rotl(x, b):
  return ((x << b) | (x >> (64 - b))) & MASK


def siphash(key, data):
  k0 = int.from_bytes(key[:8], "little")
  k1 = int.from_bytes(key[8:16], "little")

  v0 = 0x736f6d6570736575 ^ k0
  v1 = 0x646f72616e646f6d ^ k1
  v2 = 0x6c7967656e657261 ^ k0
  v3 = 0x7465646279746573 ^ k1

  state = [v0, v1, v2, v3]

  def sipround():
    a, b, c, d = state
    a = (a + b) & MASK; b = _rotl(b, 13); b ^= a; a = _rotl(a, 32)
    c = (c + d) & MASK; d = _rotl(d, 16); d ^= c
    a = (a + d) & MASK; d = _rotl(d, 21); d ^= a
    c = (c + b) & MASK; b = _rotl(b, 17); b ^= c; c = _rotl(c, 32)
    state[:] = [a, b, c, d]

  off = 0

  while off + 8 <= len(data):
    m = int.from_bytes(data[off:off + 8], "little")
    state[3] ^= m
    sipround(); sipround()
    state[0] ^= m
    off += 8

  tail = data[off:]
  b = (len(data) & 0xff) << 56
  b |= int.from_bytes(tail, "little")

  state[3] ^= b
  sipround(); sipround()
  state[0] ^= b
  state[2] ^= 0xff
  sipround(); sipround(); sipround(); sipround()

  return state[0] ^ state[1] ^ state[2] ^ state[3]


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 55], [32, 32], [0, 55]]


def module_generate_hash(word, salt, iterations=None):
  h = siphash(bytes.fromhex(salt), word)

  def swap(v):
    s = "%08x" % v
    return s[6:8] + s[4:6] + s[2:4] + s[0:2]

  return "%s%s:2:4:%s" % (swap(h & 0xffffffff), swap(h >> 32), salt)


def module_verify_hash(line):
  # perl splits on every colon and takes the hash, the salt and the word by position, so a word
  # after the salt is field 5. An empty word leaves that field absent, which perl rejects; mirror it.

  fields = line.split(b":")

  if len(fields) < 5:
    return None

  hash_hex = fields[0].decode(errors="replace")
  salt = fields[3].decode(errors="replace")
  word = fields[4]

  if len(hash_hex) != 16 or len(salt) != 32:
    return None

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
