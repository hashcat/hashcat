#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# QNX /etc/shadow before QNX 7: the digest of the salt and the password repeated iterations + 1 times,
# written @tag@digest@salt, the tag carrying ",iterations" when they are not 1000.


def generate_hash(tag, algo, word, salt, iterations):
  iterations = 1000 if iterations is None else int(iterations)

  digest = algo(salt.encode() + word * iterations + word).hexdigest()

  if iterations == 1000:
    return "@%s@%s@%s" % (tag, digest, salt)

  return "@%s,%d@%s@%s" % (tag, iterations, digest, salt)


def verify_hash(tag, algo, line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("@")

  if len(data) < 4:
    return None

  fields = data[1].split(",")

  if fields[0] != tag:
    return None

  return (generate_hash(tag, algo, word, data[3], fields[1] if len(fields) > 1 else None), word)
