#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os
import re
import subprocess

# LUKS container mode. The oracle builds a real container by running m34100.sh with this mode's id and
# the password, and returns the hash the script prints. Each run makes a fresh container with its own
# random salt, so the oracle cannot round trip its own output; these modes are exercised through
# test.sh -g (build a container, then crack it), not the oracle compare. The id comes from this
# file's name, as the perl oracle takes it from its own.

_MODULE_ID = re.match(r"m(\d+)\.py$", os.path.basename(__file__)).group(1)

_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "m34100.sh")


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  out = subprocess.run([_SCRIPT, word], capture_output=True).stdout

  return out.decode("latin-1").replace("\r", "").replace("\n", "")


def module_verify_hash(line):
  # perl splits on ':' into hash, salt and word by position

  fields = line.split(b":")

  if len(fields) < 3:
    return None

  word = fields[2]

  return (module_generate_hash(word), word)
