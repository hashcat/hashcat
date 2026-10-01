#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

# BIP39 Passphrase Recovery: the passphrase is the only unknown, with the mnemonic and derivation
# path fixed. The target is the first 16 bytes (IL) of the BIP32 master key, as hex: the master key
# is HMAC-SHA512 keyed with "Bitcoin seed" over the BIP39 seed, and that seed is PBKDF2-HMAC-SHA512
# of the mnemonic salted with "mnemonic" plus the passphrase, 2048 rounds. hashcat accepts this
# 32-hex target form alongside the real P2SH/P2PKH/P2WPKH addresses, so the oracle can verify a crack
# without deriving an address. A port of tools/test_modules/m36000.pm.

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PATH     = "m/49'/0'/0'/0/0"

HEX_CHARS = set("0123456789abcdefABCDEF")


def module_constraints():
  return [[0, 256], [-1, -1], [0, 256], [-1, -1], [-1, -1]]


def il_prefix_hex(mnemonic, passphrase):
  seed   = hashlib.pbkdf2_hmac("sha512", mnemonic, b"mnemonic" + passphrase, 2048, 64)
  master = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()

  return master[:16].hex()


def module_generate_hash(word, salt, iterations=None):
  return "%s:%s:%s" % (MNEMONIC, il_prefix_hex(MNEMONIC.encode("ascii"), word), PATH)


def module_verify_hash(line):
  # The password is everything after the last colon, as in m36000.pm: the hash itself is
  # mnemonic:target:path, none of which carry a colon.
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode("utf-8", "replace")
  word    = line[idx + 1:]

  fields = hash_in.split(":", 2)

  if len(fields) != 3:
    return None

  mnemonic, target_hex, path = fields

  if len(target_hex) != 32 or any(c not in HEX_CHARS for c in target_hex):
    return None

  new_hash = "%s:%s:%s" % (mnemonic, il_prefix_hex(mnemonic.encode("ascii"), word), path)

  if new_hash.lower() != hash_in.lower():
    return None

  return (new_hash, word)
