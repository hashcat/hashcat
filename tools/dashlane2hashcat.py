#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write the hash line of a Dashlane local database for hash-mode 34900.
#
# Dashlane 4 for Windows and macOS keeps its databases as .aes files under the profiles directory,
# %AppData%\Dashlane\profiles on Windows and ~/Library/Application Support/Dashlane/profiles on
# macOS, and exports a secure archive as a .dash file. Both start with a 32 byte salt, followed by
# the marker KWC3 when the plaintext is compressed and then the AES-256-CBC ciphertext.
#
# The line this writes is the same one that john's dashlane2john.py writes, so either tool can feed
# hash-mode 34900.
#
# Dashlane 6 and the web extension store an Argon2d KWC3 blob instead and are not covered.

import argparse
import base64
import binascii
import os
import sys

# the salt and, after it, the marker that says the plaintext is deflate compressed

SALT_LEN = 32

KWC3_MARKER = b"KWC3"

# the verifier reads far less than this, but it is what john writes, so a line from either tool is
# the same for the same file

READ_LEN = 256

# a .dash archive carries its payload base64 encoded after this marker

ARCHIVE_MARKER = b"Data BEGIN"


def archive_payload(data: bytes) -> bytes:
  lines = data.splitlines()

  for i, line in enumerate(lines):
    if ARCHIVE_MARKER not in line: continue

    if (i + 1) >= len(lines): break

    try:
      return base64.b64decode(lines[i + 1].strip(), validate=True)
    except binascii.Error:
      raise ValueError("the payload after %s is not base64" % ARCHIVE_MARKER.decode())

  raise ValueError("the archive has no payload after %s" % ARCHIVE_MARKER.decode())


def hash_line(data: bytes) -> str:
  if ARCHIVE_MARKER in data: data = archive_payload(data)

  data = data[:READ_LEN]

  if len(data) <= SALT_LEN: raise ValueError("%u bytes is too short for a salt and a ciphertext" % len(data))

  salt = data[:SALT_LEN]

  body = data[SALT_LEN:]

  if body.startswith(KWC3_MARKER) == True:
    compressed = 1

    body = body[len(KWC3_MARKER):]
  else:
    compressed = 0

  if len(body) < 16: raise ValueError("the ciphertext is %u bytes, at least one AES block is needed" % len(body))

  line = "$dashlane$%u*%s*%u*%s" % (compressed, salt.hex(), len(body), body.hex())

  return line


def main() -> int:
  parser = argparse.ArgumentParser(description="Write the hash line of a Dashlane local database for hash-mode 34900.")

  parser.add_argument("path", nargs="+", help="a Dashlane .aes database or .dash archive")

  args = parser.parse_args()

  rc = 0

  for path in args.path:
    try:
      with open(path, "rb") as fd:
        print(hash_line(fd.read()))
    except ValueError as e:
      sys.stderr.write("%s: %s\n" % (os.path.basename(path), e))

      rc = 1
    except OSError as e:
      sys.stderr.write("%s: %s\n" % (os.path.basename(path), e.strerror))

      rc = 1

  return rc


if __name__ == "__main__":
  sys.exit(main())
