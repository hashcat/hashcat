#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [0, 16], [-1, -1], [-1, -1], [-1, -1]] }

# The password goes over argv as hex. It is arbitrary bytes, and a Python b"..."
# literal can only hold ASCII, so interpolating it into the source turns every
# candidate above 0x7f into a SyntaxError.

my $PY = <<'PYCODE';
import sys
from pygost import gost34112012512

_c_digest_offsets = (
    (0, 3), (5, 1), (5, 3), (1, 2), (5, 1), (5, 3), (1, 3),
    (4, 1), (5, 3), (1, 3), (5, 0), (5, 3), (1, 3), (5, 1),
    (4, 3), (1, 3), (5, 1), (5, 2), (1, 3), (5, 1), (5, 3),
)

_512_transpose_map = (
    42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26,
    5, 47, 48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52,
    31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15,
    16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
)

HASH64_CHARS = b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
_encode64 = HASH64_CHARS.__getitem__
DEFAULT_ROUNDS = 5000

def encode_bytes(source: bytes) -> bytes:
    chunks, tail = divmod(len(source), 3)
    it = iter(source)
    out = []

    for _ in range(chunks):
        v1, v2, v3 = next(it), next(it), next(it)
        out.append(v1 & 0x3F)
        out.append(((v2 & 0x0F) << 2) | (v1 >> 6))
        out.append(((v3 & 0x03) << 4) | (v2 >> 4))
        out.append(v3 >> 2)

    if tail:
        v1 = next(it)
        if tail == 1:
            out.append(v1 & 0x3F)
            out.append(v1 >> 6)
        else:
            v2 = next(it)
            out.append(v1 & 0x3F)
            out.append(((v2 & 0x0F) << 2) | (v1 >> 6))
            out.append(v2 >> 4)

    return bytes(map(_encode64, out))

def encode_transposed_bytes(source: bytes, offsets) -> bytes:
    return encode_bytes(bytes(source[o] for o in offsets))

def gost12_512_crypt(pwd: bytes, salt: str, rounds: int) -> str:
    salt = salt.encode('ascii')
    H = gost34112012512.new
    db = H(pwd + salt + pwd).digest()

    a_ctx = H(pwd + salt)
    a_ctx.update((db * ((len(pwd) + len(db) - 1) // len(db)))[:len(pwd)])
    i = len(pwd)
    while i:
        a_ctx.update(db if i & 1 else pwd)
        i >>= 1
    da = a_ctx.digest()

    if len(pwd) < 96:
        dp = (H(pwd * len(pwd)).digest() * ((len(pwd) + 63) // 64))[:len(pwd)]
    else:
        tmp = H(pwd)
        for _ in range(len(pwd) - 1):
            tmp.update(pwd)
        dp = (tmp.digest() * ((len(pwd) + 63) // 64))[:len(pwd)]

    ds = H(salt * (16 + da[0])).digest()[: len(salt)]
    perms = [dp, dp + dp, dp + ds, dp + ds + dp, ds + dp, ds + dp + dp]
    data = [(perms[e], perms[o]) for e, o in _c_digest_offsets]

    dc = da
    blocks, tail = divmod(rounds, 42)
    for _ in range(blocks):
        for even, odd in data:
            dc = H(odd + H(dc + even).digest()).digest()
    if tail:
        for even, odd in data[: tail >> 1]:
            dc = H(odd + H(dc + even).digest()).digest()
        if tail & 1:
            dc = H(dc + data[tail >> 1][0]).digest()

    return encode_transposed_bytes(dc, _512_transpose_map).decode('ascii')

def crypt(pw, salt, rounds):
    hash = gost12_512_crypt(pw, salt, rounds)
    if rounds == DEFAULT_ROUNDS:
        return '$gost12512hash${}${}'.format(salt, hash)
    else:
        return '$gost12512hash$rounds={}${}${}'.format(rounds, salt, hash)

rounds = sys.argv[3]
if not rounds:
    rounds = DEFAULT_ROUNDS
else:
    rounds = int(rounds)
print(crypt(bytes.fromhex(sys.argv[1]), sys.argv[2], rounds), end = "")

PYCODE

sub _run
{
  my @args = @_;

  open (my $fh, "-|", "python3", "-c", $PY, @args) or return undef;

  local $/;
  my $out = <$fh>;
  close ($fh);

  return $out;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  $iter = "" unless defined $iter;

  return _run (unpack ("H*", $word), $salt, $iter);
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $index1 = index ($hash, ',', 1);
  my $index2 = index ($hash, '$', 1);

  if ($index1 != -1)
  {
    if ($index1 < $index2)
    {
      $index2 = $index1;
    }
  }

  $index2++;

  # rounds= if available
  my $iter = 0;

  if (substr ($hash, $index2, 7) eq "rounds=")
  {
    my $old_index = $index2;

    $index2 = index ($hash, '$', $index2 + 1);

    return if $index2 < 1;

    $iter = substr ($hash, $old_index + 7, $index2 - $old_index - 7);

    $index2++;
  }

  # get salt
  my $index3 = rindex ($hash, '$');

  return if $index3 < 1;

  my $salt = substr ($hash, $index2, $index3 - $index2);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

1;
