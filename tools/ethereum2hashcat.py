#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write a hashcat hash line for a Web3 Secret Storage keystore. These are the .json files an
# Ethereum wallet saves, and also the cloud backup Trust Wallet uploads to iCloud or Google Drive,
# which puts a BIP39 recovery phrase in the same envelope instead of a private key.
#
# A scrypt keystore goes to mode 15700 and a pbkdf2 one to mode 15600.
#
# Reference: https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage/

import argparse
import json
import sys

CIPHERTEXT_MAX = 256
SALT_MAX       = 32


def crypto_of(j):
  # The specification spells the member "crypto", but wallets write "Crypto" as well.

  for name in ["crypto", "Crypto"]:
    if name in j:
      return j[name]

  return None


def hex_problem(name, value):
  if isinstance(value, str) == False:
    return "%s is not a string" % name

  if (len(value) % 2) != 0:
    return "%s has an odd number of hex characters" % name

  try:
    bytes.fromhex(value)
  except ValueError:
    return "%s is not hex" % name

  return None


def int_field(name, value):
  # Wallets write these as numbers and sometimes as numeric strings, so int() is right. A field that
  # is neither has to be refused rather than raising out of the script.

  try:
    return (int(value), None)
  except (TypeError, ValueError):
    return (None, "%s is not a number" % name)


def keystore_to_line(j):
  crypto = crypto_of(j)

  if crypto is None:
    return (None, "no crypto member, so this is not a keystore")

  # Version 3 is the Web3 Secret Storage envelope the two modes implement. An xchain-crypto keystore,
  # which thorchain and thorswap wallets write, carries the same cipher and the same KDF and says
  # version 1, but it verifies with BLAKE2b rather than keccak. A line written for one of those would
  # load in mode 15600 and never crack, so the version is checked rather than assumed.

  if "version" not in j:
    return (None, "no version member, so this is not a keystore")

  version, problem = int_field("the version", j["version"])

  if problem is not None:
    return (None, problem)

  if version != 3:
    return (None, "the keystore is version %i, and this tool writes lines for version 3" % version)

  for name in ["ciphertext", "mac", "cipher", "kdf", "kdfparams"]:
    if name not in crypto:
      return (None, "the crypto member has no %s" % name)

  ciphertext = crypto["ciphertext"]
  mac        = crypto["mac"]
  kdfparams  = crypto["kdfparams"]

  if isinstance(kdfparams, dict) == False:
    return (None, "kdfparams is not an object")

  salt = kdfparams.get("salt", "")

  for name, value in [("the ciphertext", ciphertext), ("the mac", mac), ("the salt", salt)]:
    problem = hex_problem(name, value)

    if problem is not None:
      return (None, problem)

  if len(mac) != 64:
    return (None, "the mac is %i hex characters rather than 64" % len(mac))

  if len(ciphertext) == 0:
    return (None, "the ciphertext is empty")

  # hashcat takes the MAC key from bytes 16 to 32 of a 32 byte derived key, which is what the
  # specification says and what every aes-128-ctr keystore does. An aes-192-ctr or aes-256-ctr
  # keystore keys the MAC from a different part of the derived key, so a line written for one of
  # those would load and then never crack.

  if crypto["cipher"] != "aes-128-ctr":
    return (None, "the cipher is %s, and these modes hash the mac key of an aes-128-ctr keystore" % crypto["cipher"])

  dklen, problem = int_field("dklen", kdfparams.get("dklen", 32))

  if problem is not None:
    return (None, problem)

  if dklen != 32:
    return (None, "dklen is %i rather than 32" % dklen)

  if len(salt) > (SALT_MAX * 2):
    return (None, "the salt is %i bytes, and hashcat takes at most %i" % (len(salt) // 2, SALT_MAX))

  if len(ciphertext) > (CIPHERTEXT_MAX * 2):
    return (None, "the payload is %i bytes, and hashcat takes at most %i" % (len(ciphertext) // 2, CIPHERTEXT_MAX))

  kdf = crypto["kdf"]

  if kdf == "scrypt":
    for name in ["n", "r", "p"]:
      if name not in kdfparams:
        return (None, "the scrypt parameters have no %s" % name)

    numbers = {}

    for name in ["n", "r", "p"]:
      numbers[name], problem = int_field("scrypt " + name, kdfparams[name])

      if problem is not None:
        return (None, problem)

    if (numbers["n"] % 1024) != 0:
      return (None, "scrypt n is %i, and hashcat needs a multiple of 1024" % numbers["n"])

    line = "$ethereum$s*%i*%i*%i*%s*%s*%s" % (numbers["n"], numbers["r"], numbers["p"],
                                              salt, ciphertext, mac)

    return (line, None)

  if kdf in ["pbkdf2", "pbkdf2-sha256"]:
    if "c" not in kdfparams:
      return (None, "the pbkdf2 parameters have no c")

    prf = kdfparams.get("prf", "hmac-sha256")

    if prf != "hmac-sha256":
      return (None, "the pbkdf2 prf is %s, and hashcat cracks hmac-sha256" % prf)

    c, problem = int_field("the pbkdf2 c", kdfparams["c"])

    if problem is not None:
      return (None, problem)

    line = "$ethereum$p*%i*%s*%s*%s" % (c, salt, ciphertext, mac)

    return (line, None)

  return (None, "the kdf is %s, and hashcat cracks scrypt and pbkdf2 keystores" % kdf)


def file_to_line(path):
  try:
    with open(path, "rb") as fh:
      j = json.loads(fh.read().decode("utf-8", "ignore"))
  except (OSError, ValueError) as e:
    return (None, "cannot be read as json: %s" % e)

  if isinstance(j, dict) == False:
    return (None, "the file is not a json object")

  return keystore_to_line(j)


def main():
  parser = argparse.ArgumentParser(description="Write hashcat hash lines for Ethereum keystore and "
                                               "Trust Wallet cloud backup files. A scrypt keystore "
                                               "goes to mode 15700, a pbkdf2 one to mode 15600.")

  parser.add_argument("files", nargs="+", help="keystore .json files")

  args = parser.parse_args()

  failed = 0

  for path in args.files:
    # A keystore is a file somebody downloaded, so anything one file does has to stay with that
    # file. Without the catch, a crafted file ends the run and the remaining paths on the command
    # line are never looked at: json.loads raises RecursionError, not ValueError, on deeply nested
    # input, and that is only the instance we know about.

    try:
      line, problem = file_to_line(path)
    except Exception as e:
      line    = None
      problem = "cannot be read as a keystore: %s" % type(e).__name__

    if problem is not None:
      print("%s: %s" % (path, problem), file=sys.stderr)

      failed += 1

      continue

    print(line)

  if failed > 0:
    return 1

  return 0


if __name__ == "__main__":
  sys.exit(main())
