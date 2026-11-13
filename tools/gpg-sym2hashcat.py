#!/usr/bin/env python3

# extract hashes from "gpg --symmetric" messages to use with hashcat modes 17060, 17070 and 17080
#
# A symmetrically encrypted message carries two packets that matter. The SKESK packet (tag 3)
# names the cipher and the S2K that turns the passphrase into the session key, and the SEIPD
# packet (tag 18) carries the ciphertext, which ends in the SHA-1 that decides a candidate.
#
# usage: gpg-sym2hashcat.py <file.gpg> [file.gpg ...]

import base64
import sys

# the S2K hash of the message selects the hash-mode, the three differ in nothing else

HASH_MODE = {2: 17060, 8: 17070, 10: 17080}

HASH_NAME = {2: "SHA-1", 8: "SHA-256", 10: "SHA-512"}

# what the kernels implement: iterated and salted S2K, AES-256, integrity protected packet

S2K_ITERATED = 3
CIPHER_AES256 = 9
TAG_SKESK = 3
TAG_SEIPD = 18

# the m170x0 modules cap the message at GPG_DATA_MAX, because the SHA-1 that decides a candidate
# covers the whole plaintext and so the whole of it has to reach the device

GPG_DATA_MAX = 1536

# RFC 4880 5.13: 16 random bytes, the 2 that repeat the last two of them, the payload, and the
# 2 byte MDC packet header followed by its 20 byte SHA-1. An empty payload is 40 bytes, and the
# modules refuse anything shorter.

GPG_DATA_MIN = 40

ARMOR_BEGIN = "-----BEGIN PGP MESSAGE-----"
ARMOR_END = "-----END PGP MESSAGE-----"


class Unsupported(Exception):
    pass


def require(data, pos, count, what):
    # a file cut short inside a packet leaves a body shorter than its length octets promise, and a
    # hash line built from such a body never cracks, so refuse it instead of writing it out

    if pos + count > len(data):
        raise Unsupported("the %s runs past the end of the file, so the message is truncated"
                          % what)


def dearmor(data):
    # a message written with --armor is base64 between the two markers, after the headers and
    # before the checksum line, which starts with '='

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data

    if ARMOR_BEGIN not in text:
        return data

    body = text.split(ARMOR_BEGIN, 1)[1]
    body = body.split(ARMOR_END, 1)[0]

    lines = []

    for line in body.splitlines():
        line = line.strip()

        if line.startswith("="):
            break

        if not line or ":" in line:
            continue

        lines.append(line)

    return base64.b64decode("".join(lines))


def read_new_length(data, pos):
    # RFC 4880 4.2.2. A partial body length is one chunk of several, so the body is read until
    # a length that is not partial closes it. gpg writes the SEIPD packet this way.

    chunks = []

    while True:
        require(data, pos, 1, "packet length octet")

        o1 = data[pos]
        pos += 1

        partial = False

        if o1 < 192:
            length = o1
        elif o1 < 224:
            require(data, pos, 1, "two octet packet length")

            length = ((o1 - 192) << 8) + data[pos] + 192
            pos += 1
        elif o1 == 255:
            require(data, pos, 4, "five octet packet length")

            length = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
        else:
            length = 1 << (o1 & 0x1F)
            partial = True

        require(data, pos, length, "packet body")

        chunks.append(data[pos:pos + length])
        pos += length

        if partial is False:
            break

    return b"".join(chunks), pos


def read_packets(data):
    pos = 0

    while pos < len(data):
        tag_byte = data[pos]
        pos += 1

        if tag_byte & 0x80 == 0:
            raise Unsupported("not an OpenPGP packet stream")

        if tag_byte & 0x40:
            tag = tag_byte & 0x3F

            body, pos = read_new_length (data, pos)
        else:
            tag = (tag_byte >> 2) & 0x0F

            length_type = tag_byte & 0x03

            if length_type == 3:
                # RFC 4880 4.2.1 length type 3, the body is whatever is left of the file, so it
                # cannot promise more than the file holds and needs no check

                length = len(data) - pos
            else:
                if length_type == 0:
                    require(data, pos, 1, "one octet packet length")

                    length = data[pos]
                    pos += 1
                elif length_type == 1:
                    require(data, pos, 2, "two octet packet length")

                    length = int.from_bytes(data[pos:pos + 2], "big")
                    pos += 2
                else:
                    require(data, pos, 4, "four octet packet length")

                    length = int.from_bytes(data[pos:pos + 4], "big")
                    pos += 4

                require(data, pos, length, "packet body")

            body = data[pos:pos + length]
            pos += length

        yield tag, body


def parse_skesk(body):
    if len(body) < 4:
        raise Unsupported("truncated SKESK packet")

    version = body[0]

    if version != 4:
        raise Unsupported("SKESK version %d, only version 4 is covered" % version)

    cipher_algo = body[1]
    s2k_type = body[2]
    hash_algo = body[3]

    if s2k_type != S2K_ITERATED:
        raise Unsupported("S2K specifier %d, these modes need %d (iterated and salted). "
                          "Re-encrypt with --s2k-mode 3." % (s2k_type, S2K_ITERATED))

    if len(body) < 13:
        raise Unsupported("truncated iterated and salted S2K")

    salt = body[4:12]
    coded_count = body[12]

    # RFC 4880 3.7.1.3, the one octet the packet carries stands for this many bytes

    count = (16 + (coded_count & 15)) << ((coded_count >> 4) + 6)

    if len(body) > 13:
        raise Unsupported("the SKESK packet carries an encrypted session key, so the "
                          "passphrase does not key the message directly. These modes only "
                          "cover a message whose S2K key is the session key.")

    if cipher_algo != CIPHER_AES256:
        raise Unsupported("cipher algorithm %d, these modes only cover %d (AES-256). "
                          "Re-encrypt with --cipher-algo AES256."
                          % (cipher_algo, CIPHER_AES256))

    if hash_algo not in HASH_MODE:
        raise Unsupported("S2K hash algorithm %d, covered are %s"
                          % (hash_algo, ", ".join("%d (%s)" % (h, HASH_NAME[h])
                                                  for h in sorted(HASH_MODE))))

    return cipher_algo, hash_algo, salt, count


def parse_seipd(body):
    if len(body) < 2:
        raise Unsupported("truncated SEIPD packet")

    version = body[0]

    if version != 1:
        raise Unsupported("SEIPD version %d, only version 1 carries the SHA-1 these modes "
                          "check. A version 2 packet is AEAD, which they do not cover."
                          % version)

    return body[1:]


def parse_gpg(path):
    data = dearmor(open(path, "rb").read())

    skesk = None
    seipd = None

    for tag, body in read_packets(data):
        if tag == TAG_SKESK and skesk is None:
            skesk = body
        elif tag == TAG_SEIPD and seipd is None:
            seipd = body

        # Everything after these two is of no interest, and reading on would let a packet the
        # tool does not need refuse a message whose SKESK and SEIPD are both intact. A file with
        # a truncated tail behind a complete message is the case that matters.

        if (skesk is not None) and (seipd is not None):
            break

    if skesk is None:
        raise Unsupported("no SKESK packet (tag %d). This is not a passphrase encrypted "
                          "message." % TAG_SKESK)

    if seipd is None:
        raise Unsupported("no integrity protected data packet (tag %d). Re-encrypt with "
                          "--rfc4880, or without --force-aead." % TAG_SEIPD)

    cipher_algo, hash_algo, salt, count = parse_skesk(skesk)

    ciphertext = parse_seipd(seipd)

    if len(ciphertext) < GPG_DATA_MIN:
        raise Unsupported("the message holds %d bytes of ciphertext and the modes need at least "
                          "%d, which is what an empty payload comes to. This is not a whole "
                          "message." % (len(ciphertext), GPG_DATA_MIN))

    if len(ciphertext) > GPG_DATA_MAX:
        raise Unsupported("the message holds %d bytes of ciphertext and the modes cap it at "
                          "%d. The SHA-1 that decides a candidate covers the whole plaintext, "
                          "so no prefix of the message is enough."
                          % (len(ciphertext), GPG_DATA_MAX))

    line = "$gpg$*0*%d*%s*%d*%d*%d*%d*%d*%s" % (len(ciphertext), ciphertext.hex(),
                                                S2K_ITERATED, TAG_SEIPD, hash_algo,
                                                cipher_algo, count, salt.hex())

    return HASH_MODE[hash_algo], line


def main(argv):
    if len(argv) < 2:
        print("Usage: %s <file.gpg> [file.gpg ...]" % argv[0], file=sys.stderr)

        return 1

    rc = 0

    for path in argv[1:]:
        try:
            mode, line = parse_gpg(path)
        except Unsupported as e:
            print("%s: %s" % (path, e), file=sys.stderr)

            rc = 1

            continue
        except (OSError, ValueError, IndexError) as e:
            print("%s: could not read the message: %s" % (path, e), file=sys.stderr)

            rc = 1

            continue

        print(line)

        print("%s: use hashcat -m %d" % (path, mode), file=sys.stderr)

    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
