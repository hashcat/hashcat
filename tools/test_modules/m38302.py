#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import struct

from Crypto.Cipher import DES3, AES

from lib.test_helpers import random_bytes, test_iteration_parameters


def module_test_properties():
  # Salt is emitted as hex characters: 40..96 chars = 20..48 bytes.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [40, 96],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 2048}},
    'reduced': {
      'parameters': {'iterations': 2},
    },
  }


# Apple DMG (encrcdsa v2-legacy, $dmg$2). PBKDF2-HMAC-SHA1 derives a 32-byte key of which the
# first 24 bytes form a 3DES key. The first 32 bytes of the key blob are 3DES-CBC decrypted
# (IV = first 8 bytes of the iv field) and yield the AES key (16 or 32 bytes depending on the
# blob length) and a 20-byte HMAC key. The data chunk is AES-CBC decrypted with
# IV = HMAC-SHA1(hmac_key, BE32(cno))[0:16] and must contain a run of 8 zero bytes. If scp is
# set, a zero chunk with chunk number 0 is accepted as well.

SIGNATURE = "$dmg$2"


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def _pbkdf2(word, salt_bin, iterations):
  return hashlib.pbkdf2_hmac("sha1", word, salt_bin, iterations, 32)


def _unwrap_keys(dk, iv_bin, blob_bin):
  key = DES3.new(dk[:24], DES3.MODE_CBC, iv=iv_bin[:8]).decrypt(blob_bin[:32])
  aes_key  = key[:16] if len(blob_bin) == 48 else key[:32]
  hmac_key = key[:20]
  return aes_key, hmac_key


def _scan(aes_key, hmac_key, cno, chunk_bin):
  iv20 = hmac.new(hmac_key, struct.pack(">L", cno), hashlib.sha1).digest()
  pt = AES.new(aes_key, AES.MODE_CBC, iv20[:16]).decrypt(chunk_bin[: (len(chunk_bin) // 16) * 16])
  return b"\x00" * 8 in pt


def _check(word, salt_bin, iterations, iv_bin, blob_bin, cno, chunk_bin, zchunk_bin):
  aes_key, hmac_key = _unwrap_keys(_pbkdf2(word, salt_bin, iterations), iv_bin, blob_bin)
  if _scan(aes_key, hmac_key, cno, chunk_bin):
    return True
  if zchunk_bin is not None and _scan(aes_key, hmac_key, 0, zchunk_bin):
    return True
  return False


def _build_chunk(aes_key, hmac_key, cno, num_blocks):
  # plaintext with a guaranteed run of 8 zero bytes, then CBC-encrypt it
  pt = random_bytes(24) + b"\x00" * 8 + random_bytes(num_blocks * 16 - 32)
  iv20 = hmac.new(hmac_key, struct.pack(">L", cno), hashlib.sha1).digest()
  return AES.new(aes_key, AES.MODE_CBC, iv20[:16]).encrypt(pt)


def _build(word, salt_bin, iterations):
  dk = _pbkdf2(word, salt_bin, iterations)

  iv_bin = random_bytes(32)

  key_material = random_bytes(32)

  blob_len = 64 if random_bytes(1)[0] & 1 else 48

  blob_bin = DES3.new(dk[:24], DES3.MODE_CBC, iv=iv_bin[:8]).encrypt(key_material + random_bytes(blob_len - 32))

  aes_key  = key_material[:16] if blob_len == 48 else key_material[:32]
  hmac_key = key_material[:20]

  cno = int.from_bytes(random_bytes(3), "big") + 1

  chunk_bin = _build_chunk(aes_key, hmac_key, cno, 4)

  if random_bytes(1)[0] & 1:
    zchunk_bin = _build_chunk(aes_key, hmac_key, 0, 2)
  else:
    zchunk_bin = None

  return iv_bin, blob_bin, cno, chunk_bin, zchunk_bin


def module_generate_hash(word, salt, iterations=None, iv=None, keyblob=None, cno=None, chunk=None, zchunk=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  salt_bin = bytes.fromhex(salt)

  # reuse supplied material only when it actually belongs to this candidate,
  # otherwise emit fresh material so a wrong word cannot round-trip to the input hash
  if (iv is not None and keyblob is not None and cno is not None and chunk is not None
      and _check(word, salt_bin, iterations, bytes.fromhex(iv), bytes.fromhex(keyblob),
                 int(cno), bytes.fromhex(chunk),
                 bytes.fromhex(zchunk) if zchunk is not None else None)):
    iv_bin     = bytes.fromhex(iv)
    blob_bin   = bytes.fromhex(keyblob)
    cno        = int(cno)
    chunk_bin  = bytes.fromhex(chunk)
    zchunk_bin = bytes.fromhex(zchunk) if zchunk is not None else None
  else:
    iv_bin, blob_bin, cno, chunk_bin, zchunk_bin = _build(word, salt_bin, iterations)

  res = "%s*%d*%s*%d*%s*%d*%s*%d*%d*%s*" % (SIGNATURE, len(salt_bin), salt_bin.hex(),
                                           len(iv_bin), iv_bin.hex(),
                                           len(blob_bin), blob_bin.hex(),
                                           cno, len(chunk_bin), chunk_bin.hex())

  if zchunk_bin is not None:
    res += "1*%s*%d" % (zchunk_bin.hex(), iterations)
  else:
    res += "0*%d" % iterations

  return res


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if not hash_in.startswith(SIGNATURE):
    return None

  # drop a dmg2john "::::filename" suffix if present
  hash_in = hash_in.split("::::")[0]

  fields = hash_in.split("*")

  if len(fields) not in (11, 12, 13):
    return None

  # $dmg$2 * saltlen * salt * ivlen * iv * bloblen * blob * cno * datasize * chunk * scp * [zchunk] * [iterations]
  salt    = fields[2]
  iv      = fields[4]
  keyblob = fields[6]
  cno     = fields[7]
  chunk   = fields[9]
  scp     = fields[10]

  if scp == "1":
    if len(fields) < 12:
      return None
    zchunk     = fields[11]
    iterations = fields[12] if len(fields) == 13 else 1000
  else:
    zchunk     = None
    iterations = fields[11] if len(fields) == 12 else 1000

  return (module_generate_hash(word, salt, iterations, iv, keyblob, cno, chunk, zchunk), word)
