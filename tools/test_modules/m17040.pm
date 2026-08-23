#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  # Non-interpolating heredoc: Perl will NOT touch $… or backslashes inside
  my $python_code = <<'PYCODE';
#!/usr/bin/env python3
from hashlib import sha1
import sys
from random import randint
from Crypto.Cipher import CAST
from Crypto.Random import get_random_bytes
import hashlib

def s2k_iterated_salted_sha1_decoded(password: bytes, salt: bytes, count: int, out_len: int = 20) -> bytes:
    """
    OpenPGP S2K (ID=3) with SHA-1 using a *decoded* iteration count `count`.
    Produces `out_len` bytes (multiple blocks if >20), with zero-prefixing per RFC 4880.

    H_i = SHA1( (0x00 repeated i) || (salt||password repeated to `count` bytes) )

    Args:
        password: bytes
        salt: 8-byte salt (OpenPGP)
        count: decoded byte count (e.g., 329_368_576)
        out_len: desired output length in bytes

    Returns:
        `out_len` bytes of key material.
    """
    if len(salt) != 8:
        raise ValueError("salt must be exactly 8 bytes (OpenPGP)")

    base = salt + password
    if count < 0:
        raise ValueError("count must be non-negative")
    if out_len <= 0:
        return b""

    out = bytearray()
    i = 0
    while len(out) < out_len:
        h = hashlib.sha1()

        # zero-prefix for block i (only if i>0)
        if i:
            h.update(b"\x00" * i)

        # stream exactly `count` bytes of base into the hash
        remaining = count
        # feed in whole base chunks
        while remaining >= len(base):
            h.update(base)
            remaining -= len(base)
        # and a possible tail
        if remaining:
            h.update(base[:remaining])

        out.extend(h.digest())
        i += 1

    return bytes(out[:out_len])

# choose whether to do iterated S2K or salted S2K
use_iter = randint(0, 1)  # 0 = simple salted S2K, 1 = iterated
if use_iter:
    salt_iter = randint(50_000, 60_000)
else:
    salt_iter = 0  # zero => simple/salted S2K (you treated >1 as iterated)

# build plaintext message (payload) and append SHA1 of message
msg = get_random_bytes(648)            # payload bytes
sha_tail = sha1(msg).digest()          # SHA-1 of payload
plaintext = msg + sha_tail             # final plaintext to encrypt

salt = get_random_bytes(8)
nonce = get_random_bytes(8)
pw = sys.argv[1].encode()

# derive key
if salt_iter > 1:
    key = s2k_iterated_salted_sha1_decoded(pw, salt, salt_iter, out_len=16)
else:
    key = sha1(salt + pw).digest()[:16]

cipher = CAST.new(key, CAST.MODE_CFB, IV=nonce, segment_size=64)
ciphertext = cipher.encrypt(plaintext)

modulus_size = 4096
s2k_type = 3 if salt_iter > 1 else 1
cipher_mode = 3  # depends on your format; keep what your module expects

print(f"$gpg$*1*{len(ciphertext)}*{modulus_size}*{ciphertext.hex()}*{s2k_type}*254*2*{cipher_mode}*{len(nonce)}*{nonce.hex()}*{salt_iter}*{salt.hex()}")
PYCODE

  # Run python reading program from stdin; pass $word as argv[1]
  my $digest = do {
    # qx here-doc to avoid shell-quoting pitfalls
    local $ENV{PYTHONUTF8} = 1; # optional: force UTF-8 mode
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

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
