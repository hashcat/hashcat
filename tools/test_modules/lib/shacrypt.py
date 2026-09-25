#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The SHA-crypt construction (Drepper's sha256crypt and sha512crypt) over any digest, for the test
# modules of the crypt formats built on it. A port of sha_crypts () in John the Ripper's
# run/pass_gen.pl, written by Jim Fougeron and placed in the public domain.

I64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _to64(v, n):
  out = ""

  for _ in range(n):
    out += I64[v & 0x3f]
    v >>= 6

  return out


def _repeat(block, length, size):
  # the block over and over for length bytes, the last copy cut short

  out = b""

  i = length

  while i > 0:
    out += block if i > size else block[:i]
    i -= size

  return out


def crypt_bin(digest, bits, key, salt, loops):
  size = bits // 8

  b = digest(key + salt + key)

  tmp = key + salt + _repeat(b, len(key), size)

  i = len(key)

  while i > 0:
    tmp += b if (i & 1) else key
    i >>= 1

  a = digest(tmp)

  dp = digest(key * len(key))

  p = _repeat(dp, len(key), size)

  ds = digest(salt * (16 + a[0]))

  s = _repeat(ds, len(salt), size)

  c = a

  for i in range(loops):
    tmp = p if (i & 1) else c

    if i % 3:
      tmp += s

    if i % 7:
      tmp += p

    tmp += c if (i & 1) else p

    c = digest(tmp)

  if bits == 256:
    inc1, inc2, mod, end = 10, 21, 30, 0
  else:
    inc1, inc2, mod, end = 21, 22, 63, 21

  out = ""

  i = 0

  while True:
    out += _to64((c[i] << 16) | (c[(i + inc1) % mod] << 8) | c[(i + inc1 * 2) % mod], 4)
    i = (i + inc2) % mod

    if i == end:
      break

  if bits == 256:
    out += _to64((c[31] << 8) | c[30], 3)
  else:
    out += _to64(c[63], 2)

  return out


def parse(line, min_colon=0):
  # "$id$[rounds=N$]salt$hash:word" into (hash, salt, rounds or None, word)

  idx = line.find(b":", min_colon)

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  pos = hash_in.find("$", 1)

  comma = hash_in.find(",", 1)

  if comma != -1 and comma < pos:
    pos = comma

  pos += 1

  rounds = None

  if hash_in[pos:pos + 7] == "rounds=":
    end = hash_in.find("$", pos + 1)

    if end < 1:
      return None

    rounds = hash_in[pos + 7:end]
    pos = end + 1

  last = hash_in.rfind("$")

  if last < 1:
    return None

  return (hash_in, hash_in[pos:last], rounds, word)
