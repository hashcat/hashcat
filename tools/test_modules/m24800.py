#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import hmac

from lib.test_helpers import kernel_charset, split_hash_word, utf16le

# HMAC-SHA1 where the UTF-16LE password is both the key and the message. The two kernel families
# disagree on a multi byte password, so the password is widened (latin-1) or decoded (utf-8) to match
# whichever kernel test.sh is about to run; see lib/test_helpers.kernel_charset.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 27], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  unicode_word = utf16le(word, kernel_charset())

  digest = hmac.new(unicode_word, unicode_word, hashlib.sha1).digest()

  return base64.b64encode(digest).decode("ascii")


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  return (module_generate_hash(word), word)
