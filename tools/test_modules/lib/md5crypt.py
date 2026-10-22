#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# md5crypt, Poul-Henning Kamp's MD5 based crypt, with the magic ($1$, $apr1$, ...) as a parameter.

import hashlib

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _md5(data):
  return hashlib.md5(data).digest()


def to64(v, n):
  out = ""

  for _ in range(n):
    out += ITOA64[v & 0x3f]
    v >>= 6

  return out


def md5_crypt(magic, iterations, password, salt):
  # both take bytes; the result is the whole crypt string

  final = _md5(password + salt + password)

  salt = salt[:8]

  tmp = password + magic + salt

  i = len(password)

  while i > 0:
    tmp += final[:min(16, i)]
    i -= 16

  i = len(password)

  while i > 0:
    tmp += b"\x00" if (i & 1) else password[:1]
    i >>= 1

  final = _md5(tmp)

  for i in range(iterations):
    tmp = password if (i & 1) else final

    if i % 3:
      tmp += salt

    if i % 7:
      tmp += password

    tmp += final if (i & 1) else password

    final = _md5(tmp)

  f = final

  digest  = to64((f[0] << 16) | (f[6] << 8) | f[12], 4)
  digest += to64((f[1] << 16) | (f[7] << 8) | f[13], 4)
  digest += to64((f[2] << 16) | (f[8] << 8) | f[14], 4)
  digest += to64((f[3] << 16) | (f[9] << 8) | f[15], 4)
  digest += to64((f[4] << 16) | (f[10] << 8) | f[5], 4)
  digest += to64(f[11], 2)

  magic_s = magic.decode()
  salt_s = salt.decode("latin-1")

  if iterations == 1000:
    return "%s%s$%s" % (magic_s, salt_s, digest)

  return "%srounds=%d$%s$%s" % (magic_s, iterations, salt_s, digest)
