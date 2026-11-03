#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write the hash lines of a Jetico BestCrypt container (.jbc) for hash-modes 37900 to 37903.
#
# A container opens with a data block: a 1024 byte header, a 512 byte random pool, then 256 byte key
# slots. The header names the cipher, the cipher mode and the hash the key generator runs, and a 64
# entry key map says what each slot holds. Slot 0 carries the salt, and every slot the map marks as
# password based gets a line of its own, because a container can be opened by several passwords.
#
# The hash the key generator runs picks the hash-mode, and for SHA-256 the cipher mode picks it as
# well: 37900 for SHA-256 in CBC, 37901 for SHA-256 in XTS, 37902 for SHA-512 and 37903 for
# Whirlpool-512.
#
# A container whose header is itself encrypted carries none of this in clear, and is not read here.

import argparse
import os
import struct
import sys

SIGNATURE    = b"LOCOS94 "
VOLUME_LABEL = b"BC_KeyGenID"

# the key generator whose derivation the three hash-modes implement

KEYGEN_ID = 5

KEYGEN_VERSION = 3

ALG_AES = 240

MODE_CBC = 0xBC000002
MODE_XTS = 0xBC000004

HASH_SHA256    = 128
HASH_SHA512    = 10
HASH_WHIRLPOOL = 129

# the salt size that goes with each hash, which the header does not store

SALT_LEN = {HASH_SHA256: 32, HASH_SHA512: 64, HASH_WHIRLPOOL: 64}

# the hash-mode for a hash and a cipher mode. SHA-256 has one per cipher, because the XTS key takes
# a second pass of the key derivation and the CBC key does not.

HASH_MODE = {
  (HASH_SHA256,    MODE_CBC): 37900,
  (HASH_SHA256,    MODE_XTS): 37901,
  (HASH_SHA512,    MODE_CBC): 37902,
  (HASH_SHA512,    MODE_XTS): 37902,
  (HASH_WHIRLPOOL, MODE_CBC): 37903,
  (HASH_WHIRLPOOL, MODE_XTS): 37903,
}

HASH_NAME = {HASH_SHA256: "SHA-256", HASH_SHA512: "SHA-512", HASH_WHIRLPOOL: "Whirlpool-512"}

# the header fields this reads, at their offset in the data block

OFF_SIGNATURE    = 3
OFF_VOLUME_LABEL = 43
OFF_KEYGEN_ID    = 54
OFF_ITERATIONS   = 58
OFF_ALG_ID       = 128
OFF_MODE_ID      = 132
OFF_HASH_ID      = 136
OFF_KEYMAP       = 140

# the key map, one 8 byte entry per slot

KEYMAP_SLOTS = 64
KEYMAP_ENTRY = 8

# the slots themselves, which follow the header and the random pool

SLOTS_OFF = 1536
SLOT_LEN  = 256

# what a key map entry says its slot holds. A password slot is the only kind a password opens: the
# other two wrap the key for a shared secret or for a public key instead.

SLOT_PART  = -1
SLOT_EMPTY = 0
SLOT_PBE   = 1
SLOT_SSS   = 2
SLOT_PKE   = 3
SLOT_SALT  = 5


def hash_lines(data: bytes) -> tuple:
  if len(data) < SLOTS_OFF + SLOT_LEN: raise ValueError("the file is too short to hold a data block")

  if data[OFF_SIGNATURE:OFF_SIGNATURE + len (SIGNATURE)] != SIGNATURE:
    raise ValueError("no BestCrypt signature, so the header is encrypted or this is not a container")

  if data[OFF_VOLUME_LABEL:OFF_VOLUME_LABEL + len (VOLUME_LABEL)] != VOLUME_LABEL:
    raise ValueError("no key generator label, so the header is encrypted or this is not a container")

  keygen_id, keygen_version = struct.unpack_from("<HH", data, OFF_KEYGEN_ID)

  if keygen_id != KEYGEN_ID:
    raise ValueError("key generator %u is not supported, only %u is" % (keygen_id, KEYGEN_ID))

  iterations = struct.unpack_from("<I", data, OFF_ITERATIONS)[0]
  alg_id     = struct.unpack_from("<I", data, OFF_ALG_ID)[0]
  mode_id    = struct.unpack_from("<I", data, OFF_MODE_ID)[0]
  hash_id    = struct.unpack_from("<I", data, OFF_HASH_ID)[0]

  if alg_id != ALG_AES:
    raise ValueError("cipher %u is not supported, only AES is" % alg_id)

  if mode_id not in (MODE_CBC, MODE_XTS):
    raise ValueError("cipher mode 0x%08x is not supported, only CBC and XTS are" % mode_id)

  if hash_id not in SALT_LEN:
    raise ValueError("hash %u is not supported, only SHA-256, SHA-512 and Whirlpool-512 are" % hash_id)

  if iterations < 1:
    raise ValueError("the header asks for %u iterations" % iterations)

  salt_len = SALT_LEN[hash_id]

  salt = data[SLOTS_OFF:SLOTS_OFF + salt_len]

  lines = []
  other = 0

  for slot in range(KEYMAP_SLOTS):
    _, slot_type, _ = struct.unpack_from("<HhI", data, OFF_KEYMAP + (slot * KEYMAP_ENTRY))

    if slot_type in (SLOT_SSS, SLOT_PKE):
      other += 1

      continue

    if slot_type != SLOT_PBE: continue

    off = SLOTS_OFF + (slot * SLOT_LEN)

    if off + SLOT_LEN > len(data):
      raise ValueError("slot %u reaches past the end of the file" % slot)

    lines.append("$BestCrypt$1$%u$%u$%u$%u$%u$%u$%u$%s$1$%s" % (
      keygen_id,
      keygen_version,
      iterations,
      alg_id,
      mode_id,
      hash_id,
      salt_len,
      salt.hex(),
      data[off:off + SLOT_LEN].hex()))

  return (lines, HASH_MODE[(hash_id, mode_id)], hash_id, keygen_version, other)


def main() -> int:
  parser = argparse.ArgumentParser(description="Write the hash lines of a Jetico BestCrypt container (.jbc) for hash-modes 37900 to 37903.")

  parser.add_argument("path", nargs="+", help="a .jbc container file")

  args = parser.parse_args()

  rc = 0

  for path in args.path:
    name = os.path.basename(path)

    try:
      with open(path, "rb") as fd:
        lines, hash_mode, hash_id, keygen_version, other = hash_lines(fd.read(SLOTS_OFF + (KEYMAP_SLOTS * SLOT_LEN)))
    except ValueError as e:
      sys.stderr.write("%s: %s\n" % (name, e))

      rc = 1

      continue
    except OSError as e:
      sys.stderr.write("%s: %s\n" % (name, e.strerror))

      rc = 1

      continue

    if keygen_version != KEYGEN_VERSION:
      sys.stderr.write("%s: key generator version %u has not been seen before, so hashcat may refuse the line below\n" % (name, keygen_version))

    if other > 0:
      sys.stderr.write("%s: %u key slots are not password based and are left out\n" % (name, other))

    if len(lines) == 0:
      sys.stderr.write("%s: no password protected key slot\n" % name)

      rc = 1

      continue

    sys.stderr.write("%s: %u password slot(s), key generator hash %s, so hash-mode %u\n" % (name, len(lines), HASH_NAME[hash_id], hash_mode))

    for line in lines: print(line)

  return rc


if __name__ == "__main__":
  sys.exit(main())
