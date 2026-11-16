#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Extracts the crackable material from a Brave Browser profile's Preferences
# file into the $brave$ hash line accepted by hashcat mode 45800.
#
# The Brave Wallet vault lives in the profile's Preferences:
#   current: brave.wallet.encrypted_mnemonic + encryptor_salt (310000 iterations)
#   legacy:  brave.wallet.keyrings.default with password_encryptor_nonce and
#            password_encryptor_salt (100000, or 310000 once migrated)
#
# Each layout yields exactly one hash line.

import base64
import json
import sys


def extract(path):
  with open(path, errors="replace") as f:
    prefs = json.load(f)

  wallet = prefs.get("brave", {}).get("wallet", {})

  # current layout (PasswordEncryptor::CreateEncryptor, always 310000 iterations)
  em = wallet.get("encrypted_mnemonic")
  salt_b64 = wallet.get("encryptor_salt")

  if em and salt_b64:
    ct_b64 = em["ciphertext"]
    nonce_b64 = em["nonce"]

    iterations = [310000]
  else:
    # legacy layout (100000 iterations), kept by wallets never unlocked after the
    # migration landed: keyrings.default with its own nonce/salt fields
    keyrings = wallet.get("keyrings", {}).get("default", {})

    em2 = keyrings.get("encrypted_mnemonic")
    nonce_b64 = keyrings.get("password_encryptor_nonce")
    salt_b64 = keyrings.get("password_encryptor_salt")

    if not em2 or not nonce_b64 or not salt_b64:
      raise ValueError("no brave wallet vault found (neither layout)")

    ct_b64 = em2["ciphertext"] if isinstance(em2, dict) else em2

    # the migration re-encrypts into the current layout only after a successful
    # unlock, so an unmigrated legacy vault still costs 100000

    migrated = wallet.get("keyring_encryption_keys_migrated", False)

    iterations = [310000] if migrated else [100000]

  ct = base64.b64decode(ct_b64)
  nonce = base64.b64decode(nonce_b64)
  salt = base64.b64decode(salt_b64)

  if len(nonce) != 12:
    raise ValueError("unexpected nonce length %d" % len(nonce))

  if len(salt) != 32:
    raise ValueError("unexpected salt length %d" % len(salt))

  if len(ct) < 16:
    raise ValueError("ciphertext too short for ct || tag")

  lines = []

  for iters in iterations:
    lines.append("$brave$*%d*%s*%s*%s" % (iters, salt.hex(), nonce.hex(), ct.hex()))

  return lines


def main():
  if len(sys.argv) < 2:
    sys.stderr.write("usage: %s <Preferences> [...]\n" % sys.argv[0])
    sys.exit(1)

  rc = 0

  for path in sys.argv[1:]:
    try:
      for line in extract(path):
        print(line)
    except Exception as e:
      sys.stderr.write("%s: %s\n" % (path, e))
      rc = 1

  sys.exit(rc)


if __name__ == "__main__":
  main()
