#!/usr/bin/env python3

# Author......: See docs/credits.txt
# License.....: MIT

# Extracts a hashcat -m 38900 hash from a google/fscrypt login/custom protector,
# i.e. a file under <mountpoint>/.fscrypt/protectors/ (or /.fscrypt/protectors/
# for login protectors). Such a file is a ProtectorData protobuf; its password
# path is Argon2id -> HKDF-SHA256 -> HMAC-SHA256 over the wrapped key.

import sys

SOURCES = {0: "default", 1: "pam_passphrase", 2: "custom_passphrase", 3: "raw_key"}


def _varint(b, i):
  v = s = 0
  while True:
    c = b[i]
    i += 1
    v |= (c & 0x7f) << s
    s += 7
    if not c & 0x80:
      return v, i


def _fields(b):
  out, i = {}, 0
  while i < len(b):
    key, i = _varint(b, i)
    num, wt = key >> 3, key & 7
    if wt == 0:
      v, i = _varint(b, i)
    elif wt == 2:
      n, i = _varint(b, i)
      v, i = b[i:i + n], i + n
    else:
      raise ValueError("unexpected wire type %d for field %d" % (wt, num))
    out[num] = v
  return out


def process(path):
  with open(path, "rb") as f:
    data = f.read()

  try:
    p = _fields(data)
  except (ValueError, IndexError):
    sys.stderr.write("%s: not a protector protobuf\n" % path)
    return

  source = p.get(2, 0)
  if source == 3:
    sys.stderr.write("%s: raw_key protector, no password to crack\n" % path)
    return
  if 7 not in p or 4 not in p or 5 not in p:
    sys.stderr.write("%s: not a passphrase protector (%s)\n" % (path, SOURCES.get(source, source)))
    return

  costs = _fields(p[4])
  wrapped = _fields(p[7])
  t, m, par = costs.get(2), costs.get(3), costs.get(4)
  salt = p[5]
  iv, enc, mac = wrapped.get(1), wrapped.get(2), wrapped.get(3)

  if None in (t, m, par) or None in (iv, enc, mac):
    sys.stderr.write("%s: missing a required field\n" % path)
    return
  if len(salt) != 16 or len(iv) != 16 or len(enc) != 32 or len(mac) != 32:
    sys.stderr.write("%s: unexpected field length\n" % path)
    return

  # without truncation_fixed, fscrypt hashes with the parallelism cast to a uint8
  if not costs.get(5):
    par &= 0xff

  sys.stdout.write("$fscrypt$%d*%d*%d*%s*%s*%s*%s\n" % (
    t, m, par, salt.hex(), iv.hex(), enc.hex(), mac.hex()))


if __name__ == "__main__":
  if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s <protector file> [...]\n" % sys.argv[0])
    sys.exit(1)
  for arg in sys.argv[1:]:
    process(arg)
