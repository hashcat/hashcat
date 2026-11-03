#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_number

# Files written by "openssl enc" with AES-CBC and the EVP_BytesToKey key derivation, in the line
# format of John the Ripper's openssl2john.py:
#
#   $openssl$cipher$md$8$salt$last-chunks$1$kpa[$kpt]                 one block of ciphertext
#   $openssl$cipher$md$8$salt$last-chunks$0$datalen$data$kpa[$kpt]    more than one block
#
# cipher 0 is AES-256 and 1 is AES-128, md 0 is MD5, 1 SHA1 and 2 SHA256. A candidate passes when
# the last block carries valid PKCS#7 padding and then, for kpa 1, the decrypted data contains kpt,
# or, for kpa 2, at least kpt percent of it is printable ASCII.

MDS = [hashlib.md5, hashlib.sha1, hashlib.sha256]

TEXT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,-"

# the module needs 5 bytes of known plaintext, the same as OPENSSL_ENC_KPT_MIN
KPT_MIN = 5

# the module refuses an ascii check too weak to beat one false positive in 2^32. This is the
# same table it uses, from gen-ascii-min-table.py, so a generated line is one it accepts.

ASCII_MIN = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 18, 19, 20, 20, 21, 22, 23, 23, 24, 24, 25, 26, 26, 27,
  28, 28, 29, 30, 30, 31, 31, 32, 33, 33, 34, 34, 35, 35, 36, 37,
  37, 38, 38, 39, 39, 40, 41, 41, 42, 42, 43, 43, 44, 45, 45, 46,
  46, 47, 47, 48, 48, 49, 49, 50, 50, 51, 52, 52, 53, 53, 54, 54,
  55, 55, 56, 56, 57, 57, 58, 58, 59, 59, 60, 60, 61, 61, 62, 63,
  63, 64, 64, 65, 65, 66, 66, 67, 67, 68, 68, 69, 69, 70, 70, 71,
  71, 72, 72, 73, 73, 74, 74, 75, 75, 76, 76, 77, 77, 78, 78, 79,
  79, 80, 80, 81, 81, 82, 82, 83, 83, 84, 84, 85, 85, 86, 86, 87,
  87, 87, 88, 88, 89, 89, 90, 90, 91, 91, 92, 92, 93, 93, 94, 94,
  95, 95, 96, 96, 97, 97, 98, 98, 99, 99, 100, 100, 101, 101, 101, 102,
  102, 103, 103, 104, 104, 105, 105, 106, 106, 107, 107, 108, 108, 109, 109, 110,
  110, 110, 111, 111, 112, 112, 113, 113, 114, 114, 115, 115, 116, 116, 117, 117,
  118, 118, 118, 119, 119, 120, 120, 121, 121, 122, 122, 123, 123, 124, 124, 125,
  125, 125, 126, 126, 127, 127, 128, 128, 129, 129, 130, 130, 131, 131, 132, 132,
  132,
]

def _min_pct(window):
  # the smallest ascii share the module accepts for this window, or 0 if none does

  if window >= len(ASCII_MIN):
    return 0

  need = ASCII_MIN[window]

  if need == 0:
    return 0

  for pct in range(1, 101):
    if -(-pct * window // 100) >= need:
      return pct

  return 0


def _bytes_to_key(word, salt, cipher, md):
  need = (32 if cipher == 0 else 16) + 16

  out = b""
  prev = b""

  while len(out) < need:
    prev = MDS[md](prev + word + salt).digest()

    out += prev

  key_len = need - 16

  return out[:key_len], out[key_len:need]


def _pkcs_len(block_data):
  pad = block_data[-1]

  if (pad < 1) or (pad > 16):
    return -1

  if block_data[-pad:] != bytes([pad]) * pad:
    return -1

  length = len(block_data) - pad

  return length


def _ascii_ok(data, length, pct):
  if length < 0:
    return False

  nascii = 0

  for c in data[:length]:
    if (c == 0x0a) or (c == 0x0d) or ((c >= 32) and (c < 127)):
      nascii += 1

  ok = (nascii * 100) >= (pct * length)

  return ok


def _check(word, f):
  key, iv = _bytes_to_key(word, f["salt"], f["cipher"], f["md"])

  last = f["last"]

  if f["inlined"] == 1:
    tail = AES.new(key, AES.MODE_CBC, iv).decrypt(last[0:16])
  else:
    tail = AES.new(key, AES.MODE_CBC, last[0:16]).decrypt(last[16:32])

  if _pkcs_len(tail) < 0:
    return False

  if f["kpa"] == 0:
    return True

  if f["inlined"] == 1:
    plain = tail

    length = _pkcs_len(plain)
  else:
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(f["data"])

    length = _pkcs_len(plain)

    if (length < 0) and (len(plain) >= 256):
      length = len(plain)

  if f["kpa"] == 1:
    found = plain.find(f["kpt"]) >= 0

    return found

  pct = int(f["kpt"])

  if pct == 0:
    pct = 90

  ok = _ascii_ok(plain, length, pct)

  return ok


def _parse(hash_in):
  if hash_in.startswith("$openssl$") is False:
    return None

  parts = hash_in[9:].split("$")

  if len(parts) < 7:
    return None

  f = {}

  f["cipher"]  = int(parts[0])
  f["md"]      = int(parts[1])
  f["salt"]    = bytes.fromhex(parts[3])
  f["last"]    = bytes.fromhex(parts[4])
  f["inlined"] = int(parts[5])

  rest = parts[6:]

  f["data"] = b""

  if f["inlined"] == 0:
    f["data"] = bytes.fromhex(rest[1])

    rest = rest[2:]

  f["kpa"] = int(rest[0])
  f["kpt"] = "$".join(rest[1:]).encode("latin-1")

  return f


def _line(salt, cipher, md, ct, kpa, kpt):
  head = "$openssl$%u$%u$8$%s" % (cipher, md, salt.hex())

  tail = "$%u" % kpa

  if kpa != 0:
    tail += "$" + kpt.decode("latin-1")

  if len(ct) <= 16:
    line = "%s$%s$1%s" % (head, ct[-16:].hex(), tail)

    return line

  data = ct[:256]

  line = "%s$%s$0$%u$%s%s" % (head, ct[-32:].hex(), len(data), data.hex(), tail)

  return line


def module_constraints():
  return [[0, 256], [8, 8], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, line=None):
  if line is not None:
    f = _parse(line)

    if _check(word, f) is True:
      return line

    # anything that is not the line itself tells the runner this password did not crack it

    return line + "$"

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  cipher = random_number(0, 1)
  md     = random_number(0, 2)

  # mostly short files, which openssl2john inlines or keeps whole, and some longer than the 256
  # bytes it keeps

  plain_len = [random_number(KPT_MIN, 15), random_number(16, 255), random_number(256, 400)][random_number(0, 2)]

  plain = "".join(TEXT_CHARS[random_number(0, len(TEXT_CHARS) - 1)] for _ in range(plain_len)).encode()

  pad = 16 - (len(plain) % 16)

  key, iv = _bytes_to_key(word, salt_bytes, cipher, md)

  ct = AES.new(key, AES.MODE_CBC, iv).encrypt(plain + bytes([pad]) * pad)

  # the module refuses a line whose checks leave a false positive rate worse than one in 2^32, so
  # only generate lines it accepts. The padding alone never qualifies, a known plaintext needs
  # KPT_MIN bytes, and an ascii share needs a window the parser can count on, which is 16 bytes
  # short of what the line carries.

  window  = 0 if len(ct) <= 16 else max(len(ct) - 16, 0)
  pct_min = _min_pct(window)

  kpa = random_number(1, 2) if pct_min > 0 else 1

  if kpa == 1:
    visible = plain[:min(len(plain), 16 if len(ct) <= 16 else 256)]

    start = random_number(0, len(visible) - KPT_MIN)
    end   = random_number(start + KPT_MIN, min(len(visible), start + 24))

    kpt = visible[start:end]
  else:
    kpt = str(random_number(pct_min, 100)).encode()

  return _line(salt_bytes, cipher, md, ct, kpa, kpt)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode("latin-1"), line[idx + 1:]

  try:
    f = _parse(hash_in)
  except (ValueError, IndexError):
    return None

  if f is None:
    return None

  new_hash = module_generate_hash(word, None, None, hash_in)

  return (new_hash, word)
