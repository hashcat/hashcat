#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import random_hex_string, split_hash_word

# AWS4-HMAC-SHA256 (Signature v4): a chain of HMAC-SHA256 over the date, region, service and
# aws4_request keyed from "AWS4"+password, then over the string to sign.


def module_constraints():
  return [[0, 256], [8, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, region="us-east-1", service="s3", canonical=None):
  if canonical is None:
    canonical = random_hex_string(64)

  # Only 8 and 16 character salts occur in real hashes; single () also draws 9 to 15. To make every
  # length round trip, the long date is always the 8 digit date plus T000000Z (16 chars), which for a
  # 16 char salt is the salt itself.

  if len(salt) == 16:
    longdate, date = salt, salt[:8]
  else:
    date, longdate = salt[:8], "%sT000000Z" % salt[:8]

  def h(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()

  k = h(("AWS4" + word.decode("latin-1")).encode("latin-1"), date)
  k = h(k, region)
  k = h(k, service)
  k = h(k, "aws4_request")

  sts = "AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s" % (longdate, date, region, service, canonical)

  digest = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()

  return "$AWS-Sig-v4$0$%s$%s$%s$%s$%s" % (longdate, region, service, canonical, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$AWS-Sig-v4$0$"):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 8 or len(fields[3]) != 16:
    return None


  return (module_generate_hash(word, fields[3], None, fields[4], fields[5], fields[6]), word)
