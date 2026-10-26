#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# SunMD5. 4096 base rounds (plus an optional rounds= count) of md5, where each round optionally mixes
# in a fixed passage of Hamlet before the round number. The passage and the coin-flip bit selection
# reproduce Muffett's original implementation exactly, including its quirks, or the hash will not
# match.

CONSTANT_PHRASE = (
  "To be, or not to be,--that is the question:--\n"
  "Whether 'tis nobler in the mind to suffer\n"
  "The slings and arrows of outrageous fortune\n"
  "Or to take arms against a sea of troubles,\n"
  "And by opposing end them?--To die,--to sleep,--\n"
  "No more; and by a sleep to say we end\n"
  "The heartache, and the thousand natural shocks\n"
  "That flesh is heir to,--'tis a consummation\n"
  "Devoutly to be wish'd. To die,--to sleep;--\n"
  "To sleep! perchance to dream:--ay, there's the rub;\n"
  "For in that sleep of death what dreams may come,\n"
  "When we have shuffled off this mortal coil,\n"
  "Must give us pause: there's the respect\n"
  "That makes calamity of so long life;\n"
  "For who would bear the whips and scorns of time,\n"
  "The oppressor's wrong, the proud man's contumely,\n"
  "The pangs of despis'd love, the law's delay,\n"
  "The insolence of office, and the spurns\n"
  "That patient merit of the unworthy takes,\n"
  "When he himself might his quietus make\n"
  "With a bare bodkin? who would these fardels bear,\n"
  "To grunt and sweat under a weary life,\n"
  "But that the dread of something after death,--\n"
  "The undiscover'd country, from whose bourn\n"
  "No traveller returns,--puzzles the will,\n"
  "And makes us rather bear those ills we have\n"
  "Than fly to others that we know not of?\n"
  "Thus conscience does make cowards of us all;\n"
  "And thus the native hue of resolution\n"
  "Is sicklied o'er with the pale cast of thought;\n"
  "And enterprises of great pith and moment,\n"
  "With this regard, their currents turn awry,\n"
  "And lose the name of action.--Soft you now!\n"
  "The fair Ophelia!--Nymph, in thy orisons\n"
  "Be all my sins remember'd.\n"
).encode("ascii")

CONSTANT_PHRASE_WITH_NUL = CONSTANT_PHRASE + b"\x00"

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _md5bit(digest, n):
  n %= 128

  return (digest[n // 8] >> (n % 8)) & 1


def _coin(digest, rnd):
  db = digest[:16]

  x = 0
  y = 0

  for i in range(8):
    a = db[(i + 0) % 16]
    b = db[(i + 3) % 16]
    v = db[(a >> (b % 5)) % 16]
    if b & (1 << (a % 8)):
      v >>= 1
    x |= _md5bit(digest, v) << i

    a = db[(i + 8) % 16]
    b = db[(i + 11) % 16]
    v = db[(a >> (b % 5)) % 16]
    if b & (1 << (a % 8)):
      v >>= 1
    y |= _md5bit(digest, v) << i

  if _md5bit(digest, rnd):
    x >>= 1

  if _md5bit(digest, rnd + 64):
    y >>= 1

  return _md5bit(digest, x & 0x7f) ^ _md5bit(digest, y & 0x7f)


def _to64(v, n):
  ret = ""

  while n - 1 >= 0:
    n -= 1
    ret += ITOA64[v & 0x3f]
    v >>= 6

  return ret


def module_constraints():
  return [[0, 256], [1, 8], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  extra_rounds = 0 if iterations is None else int(iterations)

  total_rounds = 4096 + extra_rounds

  if extra_rounds > 0:
    puresalt = "$md5,rounds=%d$%s$" % (extra_rounds, salt)
  else:
    puresalt = "$md5$%s$" % salt

  digest = hashlib.md5(word + puresalt.encode("latin-1")).digest()

  for rnd in range(total_rounds):
    buf = digest

    if _coin(digest, rnd) == 1:
      buf += CONSTANT_PHRASE_WITH_NUL

    buf += ("%d" % rnd).encode("ascii")

    digest = hashlib.md5(buf).digest()

  out = ""
  out += _to64((digest[0] << 16) | (digest[6] << 8) | digest[12], 4)
  out += _to64((digest[1] << 16) | (digest[7] << 8) | digest[13], 4)
  out += _to64((digest[2] << 16) | (digest[8] << 8) | digest[14], 4)
  out += _to64((digest[3] << 16) | (digest[9] << 8) | digest[15], 4)
  out += _to64((digest[4] << 16) | (digest[10] << 8) | digest[5], 4)
  out += _to64(digest[11], 2)

  return "%s$%s" % (puresalt, out)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$md5"):
    return None

  pos = 4

  if pos >= len(hash_in) or hash_in[pos] not in (",", "$"):
    return None

  pos += 1

  extra_rounds = 0

  if hash_in[pos:pos + 7] == "rounds=":
    pos += 7
    end = hash_in.find("$", pos)
    if end < 0:
      return None
    extra_rounds = int(hash_in[pos:end])
    pos = end + 1

  last_sep = hash_in.rfind("$")

  if last_sep < pos:
    return None

  salt = hash_in[pos:last_sep].rstrip("$")

  return (module_generate_hash(word, salt, extra_rounds if extra_rounds > 0 else None), word)
