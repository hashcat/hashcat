#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

# Linux Kernel Crypto API (2.4). This is a known-plaintext attack, not a hash:
#
#   $cryptoapi$<type>$<key size>$<IV>$<plaintext>$<ciphertext>
#
# where type picks one of five digests crossed with one of three ciphers, key
# size is 0, 1 or 2 for 128, 192 or 256 bits, and the three trailing fields are
# 16 bytes each. A password is right when encrypting plaintext XOR IV under the
# key derived from it reproduces the ciphertext, which is one CBC block.
#
# The key is dm-crypt's "plain" derivation: the digest of the password, cut to
# the key size. A digest too short to fill the key (SHA-1 and RIPEMD-160, both
# 20 bytes) is topped up from a second digest, of the password with a literal
# "A" in front of it, which is what the kernels spell out as
# ctx.w0[0] = 0x41000000 with ctx.len = 1.
#
# This oracle covers the AES types, 0, 3, 6 and 9, across all three key sizes,
# which is every key-derivation path the mode has: the two short digests that
# need the second pass and the two long ones that do not. Serpent, Twofish and
# Whirlpool are left out because nothing available to a .pm implements them.
#
# They are not left untested, though. test.sh already runs 14500 against the
# cryptoloop containers in tools/cl_tests, listed under CL_MODES by the kernel
# number each one selects, and those cover the Serpent and Twofish ciphers.
# What they do not cover is a random password per run or the -a 0 and -a 1
# kernels, since every container is cracked with one fixed -a 3 mask, and that
# is the gap this oracle fills.

sub module_constraints { [[0, 64], [-1, -1], [0, 31], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;

  my $python_code = <<'PYCODE';
#!/usr/bin/env python3
import sys, hashlib
from random import choice, randint
from os import urandom
from Crypto.Cipher import AES
from Crypto.Hash import RIPEMD160

password = sys.argv[1].encode()

# type -> digest, for the AES ciphers only
DIGESTS = {
    0: lambda b: hashlib.sha1(b).digest(),
    3: lambda b: hashlib.sha256(b).digest(),
    6: lambda b: hashlib.sha512(b).digest(),
    9: lambda b: RIPEMD160.new(b).digest(),
}

hash_type = choice(sorted(DIGESTS))
key_size  = randint(0, 2)
key_len   = (16, 24, 32)[key_size]

digest = DIGESTS[hash_type]

key = digest(password)
if len(key) < key_len:
    # too short to fill the key, so the rest comes from digest("A" || password)
    key = key + digest(b"A" + password)
key = key[:key_len]

iv = urandom(16)
pt = urandom(16)
ct = AES.new(key, AES.MODE_ECB).encrypt(bytes(a ^ b for a, b in zip(pt, iv)))

print("$cryptoapi$%d$%d$%s$%s$%s" % (hash_type, key_size, iv.hex(), pt.hex(), ct.hex()))
PYCODE

  my $digest = do {
    local $ENV{PYTHONUTF8} = 1;
    qx{python3 - "$word" <<'PY'
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

  return unless substr ($hash_in, 0, 12) eq '$cryptoapi$';

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word);

  return ($new_hash, $word);
}

1;
