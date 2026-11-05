#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

# Android FDE from 5.0 on, the footers whose kdf_type is one of the two keymaster variants that sign
# a 256 byte message. The stored string is
#
#   $androidfde$<kdf type>$<N>$<r>$<p>$<salt>$<scrypted_intermediate_key>$<rsa n>$<rsa d>
#
# and the chain from cryptfs.c's scrypt_keymaster () is
#
#   ikey1(32)   = scrypt (password, salt, N, r, p)
#   to_sign(256) = ikey1 at byte offset 1 for kdf_type 5, at offset 0 for kdf_type 4, zeros around
#   signature(256) = to_sign ^ d mod n, the raw RSA private key operation
#   ikey2(32)   = scrypt (signature, salt, N, r, p)
#   check: scrypt (ikey2[0:16], salt, N, r, p, 32) == footer.scrypted_intermediate_key
#
# The kdf type is the footer's own field, so a plain KDF_SCRYPT footer carries a 2 and belongs to
# mode 44000 instead. N, r and p are values; the footer holds them as base 2 logarithms, so its
# defaults of { 15, 3, 1 } are what N=32768, r=8, p=2 below means.
#
# KDF_SCRYPT_KEYMASTER_BADLY_PADDED is the offset 0 variant, and at that offset the message's top
# byte is the first byte of ikey1, so it exceeds the modulus for about a quarter of all candidates.
# That is the flaw the AOSP comment names, and it is not a reason to skip those candidates: the raw
# private key operation is m^d mod n, which is defined for m >= n and is what the device computed.
#
# Note the length of the third call: cryptfs.c copies KEY_LEN_BYTES into intermediate_key, so the
# last scrypt runs over the first 16 bytes of ikey2 and not over all 32.
#
# The RSA key lives in the hash line because it is not in the footer in usable form: it is inside
# keymaster_blob, encrypted under a hardware bound key the user has to extract off the device
# first. The key below is a throwaway RSA-2048 key, fixed so a vector costs no keygen, and it is
# the hash rather than the password, so one key serves every vector.

KDF_SCRYPT_KEYMASTER_BADLY_PADDED = 4
KDF_SCRYPT_KEYMASTER              = 5

SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 2

RSA_N = 0xafbe0089c719a57972e83c1f2c48fea06e4ad9b9297f435bc715c418fe9edf2dc2a4d346aeaff6062f97ce74d77470b4ace6ba75a4ba744267d66b71983e07cc3187c92b539cb766bbf31f04d29f4f868b210289099d6e408051a3d5c7367c44eb175075ee75ff752975b8607dfea60fde890fcb3626343fcd812c4347cc66b7925afda94083d9add37dfc65b2584fd61b891303153c2bd6909162c46ffd2c5c9207d4e56278cb4127828a7342f8ed408f447e8804499b5295ed15186b35fcb19840bac2fbda66a2815145213adc786a606f8bf36c0c90b0828f9498d376241eec0f2ddf61e312f55785b88e33c98a1fa65872bcced915f23a5b4d69e9093815
RSA_D = 0x0f60ce2dc03b1d887cd6570a7846d3e728778ac941d915c5166cf069aa802ef1d3663669a938130c740631e5f60385a83db7fbe976f66cdd71b628d53a17f57937fd548c62c6e4228c8047fed54a64fc5638d77eb3d56f941bd669027829eba2613afb4ab288e747728f0f48fc4577f50c094cd540a203b0f093e4d2675a3ac3a0a25ed46039f66cbf2f79e3d4cc016307c12c0b1a0e10505645e1d05f94bcd311f452f70a0e8de7b3b9003271a57dc774fc7095147a7a50eed342f0f66c4b922dbb645cc0e40158e977e4321ca3e9597bce625f33cb5ed98d41cb9afd708cfa5f07fb83a011416b6d9ce5f707d5c301d400a0121598b984bfd432e42b2fc561

SIK_LEN = 32


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


def _scrypt(password, salt_raw, n, r, p, dklen):
  return hashlib.scrypt(password, salt=salt_raw, n=n, r=r, p=p, dklen=dklen,
                        maxmem=(128 * n * r * (p + 2)))


def _to_sign(ikey1: bytes, kdf_type: int) -> bytes:
  # keymaster_sign_object (): memset 0, then memcpy (to_sign + off, object, min (256 - off, 32))
  off = 0 if kdf_type == KDF_SCRYPT_KEYMASTER_BADLY_PADDED else 1

  buf = bytearray(256)

  buf[off:off + len(ikey1)] = ikey1

  return bytes(buf)


def _sik(word, salt_raw, n, r, p, kdf_type):
  ikey1 = _scrypt(word, salt_raw, n, r, p, 32)

  m = int.from_bytes(_to_sign(ikey1, kdf_type), "big")

  signature = pow(m, RSA_D, RSA_N).to_bytes(256, "big")

  ikey2 = _scrypt(signature, salt_raw, n, r, p, 32)

  return _scrypt(ikey2[:16], salt_raw, n, r, p, SIK_LEN)


def _build(n, r, p, salt, sik, kdf_type):
  return "$androidfde$%d$%d$%d$%d$%s$%s$%0512x$%0512x" % (
    kdf_type, n, r, p, salt, sik.hex(), RSA_N, RSA_D)


def module_generate_hash(word, salt, iterations=None, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
  # Both variants are one hash-mode and the vector's own salt picks which one it is, so a run covers
  # the offset 0 path as well as the offset 1 path rather than only the one ST_HASH carries. The
  # runner draws a fresh salt per vector, so this comes out near enough an even split.
  salt_raw = bytes.fromhex(salt)

  kdf_type = KDF_SCRYPT_KEYMASTER

  if len(salt_raw) > 0 and (salt_raw[0] % 2) == 0:
    kdf_type = KDF_SCRYPT_KEYMASTER_BADLY_PADDED

  sik = _sik(word, salt_raw, n, r, p, kdf_type)

  if sik is None:
    return None

  return _build(n, r, p, salt, sik, kdf_type)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  parts = hash_in.split(b"$")

  if len(parts) != 10 or parts[1] != b"androidfde":
    return None

  try:
    kdf_type = int(parts[2])
    n        = int(parts[3])
    r        = int(parts[4])
    p        = int(parts[5])
    salt     = parts[6].decode("ascii")
    sik      = bytes.fromhex(parts[7].decode("ascii"))
    rsa_n    = int(parts[8], 16)
    rsa_d    = int(parts[9], 16)
  except (UnicodeDecodeError, ValueError):
    return None

  if kdf_type not in (KDF_SCRYPT_KEYMASTER, KDF_SCRYPT_KEYMASTER_BADLY_PADDED):
    return None

  if len(salt) != 32 or len(sik) != SIK_LEN:
    return None

  if n < 2 or (n & (n - 1)) != 0 or r < 1 or p < 1:
    return None

  if rsa_n != RSA_N or rsa_d != RSA_D:
    return None

  if _sik(word, bytes.fromhex(salt), n, r, p, kdf_type) != sik:
    return None

  return (_build(n, r, p, salt, sik, kdf_type), word)
