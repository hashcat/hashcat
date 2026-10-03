#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# NetIQ SSPR: the digest of the salt field and the password, then of the digest, iterations times in
# all, written $sspr$version$iterations$salt$hex. The salt field is NONE, a salt in base64 or a raw
# salt, depending on the mode.


def iterate(algo, data, iterations):
  digest = algo(data).digest()

  for _ in range(1, iterations):
    digest = algo(digest).digest()

  return digest


def generate_hash(version, algo, iterations, word, salt_field):
  data = (b"" if salt_field == "NONE" else salt_field.encode()) + word

  return "$sspr$%d$%d$%s$%s" % (version, iterations, salt_field, iterate(algo, data, iterations).hex())


def parse(version, iterations, line):
  # (salt field, word) out of the line, or None

  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  prefix = "$sspr$%d$%d$" % (version, iterations)

  if not hash_in.startswith(prefix):
    return None

  return (hash_in[len(prefix):].split("$")[0], word)
