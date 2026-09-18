#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

# Password Safe v2. Like m05200 this is OPTS_TYPE_BINARY_HASHFILE, so the
# oracle prints the file in base64 and test.sh decodes it back before handing
# it to hashcat.
#
# The header module_hash_decode reads is 56 bytes:
#
#   RandStuff(8) || RandHash(20) || Salt(20, unused) || IV(8, unused)
#
# and RandHash comes out of
#
#   key    = SHA1(RandStuff || 0x00 0x00 || password)
#   block  = Blowfish-encrypt(RandStuff) x 1000, under that key
#   digest = SHA1(block || 0x00 0x00)
#
# with two quirks the kernel reproduces and this has to match. RandStuff is fed
# to Blowfish as two little-endian words rather than the usual big-endian pair,
# and the final SHA-1 starts from an all-zero state instead of the standard
# initial values ("yep, not a bug", as m09000-pure.cl puts it).
#
# The password is capped at 45 characters because the kernel runs exactly one
# SHA-1 block, and 10 bytes of it are already spent on RandStuff and the two
# zero bytes.

sub module_constraints { [[0, 45], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $python_code = <<'PYCODE';
#!/usr/bin/env python3
import sys, base64, hashlib, os, struct
from Crypto.Cipher import Blowfish


def sha1_zero_state(msg: bytes) -> bytes:
    # SHA-1 with the initial state left at zero, which is what the kernel does
    h = [0, 0, 0, 0, 0]

    m = msg + b"\x80"
    while len(m) % 64 != 56:
        m += b"\x00"
    m += struct.pack(">Q", len(msg) * 8)

    for off in range(0, len(m), 64):
        w = list(struct.unpack(">16I", m[off:off + 64]))
        for i in range(16, 80):
            v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            w.append(((v << 1) | (v >> 31)) & 0xFFFFFFFF)

        a, b, c, d, e = h
        for i in range(80):
            if i < 20:
                f, k = (b & c) | ((~b & 0xFFFFFFFF) & d), 0x5A827999
            elif i < 40:
                f, k = b ^ c ^ d, 0x6ED9EBA1
            elif i < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                f, k = b ^ c ^ d, 0xCA62C1D6
            t = ((((a << 5) | (a >> 27)) & 0xFFFFFFFF) + f + e + k + w[i]) & 0xFFFFFFFF
            e, d, c, b, a = d, c, ((b << 30) | (b >> 2)) & 0xFFFFFFFF, a, t

        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e])]

    return b"".join(struct.pack(">I", x) for x in h)


password   = sys.argv[1].encode()
rand_stuff = bytes.fromhex(sys.argv[2])

key = hashlib.sha1(rand_stuff + b"\x00\x00" + password).digest()

bf    = Blowfish.new(key, Blowfish.MODE_ECB)
block = struct.pack(">II", *struct.unpack("<II", rand_stuff))
for _ in range(1000):
    block = bf.encrypt(block)

rand_hash = sha1_zero_state(struct.pack("<II", *struct.unpack(">II", block)) + b"\x00\x00")

header = rand_stuff + rand_hash + os.urandom(20) + os.urandom(8)

print(base64.b64encode(header + os.urandom(112)).decode())
PYCODE

  my $digest = do {
    local $ENV{PYTHONUTF8} = 1;
    qx{python3 - "$word" "$salt" <<'PY'
$python_code
PY
};
  };

  $digest =~ s/[\r\n]//g;

  return $digest;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ":");

  return if $idx < 1;

  my $hash_in = substr ($line, 0, $idx);
  my $word    = substr ($line, $idx + 1);

  return unless defined $hash_in;
  return unless defined $word;

  my $header = MIME::Base64::decode_base64 ($hash_in);

  return unless length $header >= 56;

  my $salt = unpack ("H*", substr ($header, 0, 8));

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
