#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# OpenSSH private keys in the openssh-key-v1 container, keyed with bcrypt-pbkdf, which
# lib/bcrypt_pbkdf.py implements.

import struct

from Crypto.Cipher import AES

from lib.bcrypt_pbkdf import bcrypt_pbkdf


# AES through ECB blocks, so CTR and CBC share one shape and neither depends on a padding convention.

def aes_ctr(key, iv, data):
  cipher = AES.new(key, AES.MODE_ECB)
  ctr    = bytearray(iv)
  out    = bytearray()

  for i in range(0, len(data), 16):
    ks    = cipher.encrypt(bytes(ctr))
    block = data[i:i + 16]

    out += bytes(a ^ b for a, b in zip(block, ks[:len(block)]))

    for j in range(15, -1, -1):
      ctr[j] = (ctr[j] + 1) & 0xff

      if ctr[j] != 0:
        break

  return bytes(out)


def aes_cbc_encrypt(key, iv, data):
  cipher = AES.new(key, AES.MODE_ECB)
  prev   = iv
  out    = bytearray()

  for i in range(0, len(data), 16):
    blk = cipher.encrypt(bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))

    out += blk

    prev = blk

  return bytes(out)


def aes_cbc_decrypt(key, iv, data):
  cipher = AES.new(key, AES.MODE_ECB)
  prev   = iv
  out    = bytearray()

  for i in range(0, len(data), 16):
    blk = data[i:i + 16]

    out += bytes(a ^ b for a, b in zip(cipher.decrypt(blk), prev))

    prev = blk

  return bytes(out)


def ssh_encrypt(cid, key, iv, data):
  return aes_cbc_encrypt(key, iv, data) if cid == 2 else aes_ctr(key, iv, data)


def ssh_decrypt(cid, key, iv, data):
  return aes_cbc_decrypt(key, iv, data) if cid == 2 else aes_ctr(key, iv, data)


def sshstr(s):
  return struct.pack(">I", len(s)) + s


def build_header(salt_bin, rounds, cid, enc_len):
  ciphername = b"aes256-cbc" if cid == 2 else b"aes256-ctr"

  # nothing in this mode inspects the public key, so a constant keeps the hash reproducible

  pub = b"\x01" * 32

  return (b"openssh-key-v1\x00"
          + sshstr(ciphername)
          + sshstr(b"bcrypt")
          + sshstr(sshstr(salt_bin) + struct.pack(">I", rounds))
          + struct.pack(">I", 1)
          + sshstr(sshstr(b"ssh-ed25519") + sshstr(pub))
          + struct.pack(">I", enc_len))


def default_plain():
  # checkint1 == checkint2 is what marks a correct decryption

  checkint = 0x01020304

  pub = b"\x01" * 32

  plain = (struct.pack(">I", checkint)
           + struct.pack(">I", checkint)
           + sshstr(b"ssh-ed25519")
           + sshstr(pub)
           + sshstr(pub + pub)
           + sshstr(b"hashcat"))

  padlen = (16 - (len(plain) % 16)) % 16

  plain += bytes(range(1, padlen + 1))

  return plain


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, cid=6, blob=None, ct_off=None):
  # The default round count is kept low on purpose: bcrypt_pbkdf is implemented in pure Python here
  # and is the whole cost of the test, so a realistic 16 makes a bridged run, which runs the KDF once
  # per candidate, take minutes. The test exercises the format and the kernel, not a real work
  # factor, so 4 rounds is plenty, and hashcat reads the count out of the hash so the crack is right.
  rounds = int(iterations) if (iterations is not None and str(iterations) != "") else 4

  cid = int(cid)

  salt_bin = bytes.fromhex(salt)

  dk = bcrypt_pbkdf(word, salt_bin, rounds, 48)

  key = dk[0:32]
  iv  = dk[32:48]

  if blob is not None:
    # Verify path: recover the plaintext from the supplied blob. The decryption is only trusted
    # when the two check integers agree, otherwise fall through to the generated body, which yields
    # a different line and so fails the comparison.

    enc = blob[ct_off:]
    enc = enc[:len(enc) & ~15]

    dec = ssh_decrypt(cid, key, iv, enc)

    c1, c2 = struct.unpack(">II", dec[0:8])

    if c1 == c2:
      header = blob[0:ct_off]

      out = header + ssh_encrypt(cid, key, iv, dec)

      return "$sshng$%d$%d$%s$%d$%s$%d$%d" % (
        cid, len(salt_bin), salt_bin.hex(), len(out), out.hex(), rounds, ct_off)

  plain = default_plain()

  enc    = ssh_encrypt(cid, key, iv, plain)
  header = build_header(salt_bin, rounds, cid, len(enc))
  out    = header + enc

  return "$sshng$%d$%d$%s$%d$%s$%d$%d" % (
    cid, len(salt_bin), salt_bin.hex(), len(out), out.hex(), rounds, len(header))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[:7] != "$sshng$":
    return None

  parts = hash_in.split("$")

  if len(parts) < 9:
    return None

  _, signature, cid, salt_len, salt, data_len, data, rounds, ct_off = parts[:9]

  if signature != "sshng":
    return None

  try:
    cid    = int(cid)
    ct_off = int(ct_off)
    blob   = bytes.fromhex(data)
  except ValueError:
    return None

  # the six token form is the legacy PEM layout of -m 22911..22951

  if cid not in (2, 6):
    return None

  if len(blob) != int(data_len):
    return None

  if ct_off + 16 > len(blob):
    return None

  new_hash = module_generate_hash(word, salt, rounds, cid, blob, ct_off)

  return (new_hash, word)
