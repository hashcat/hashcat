#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

# The password goes over argv as hex. It is arbitrary bytes, and a Python b"..."
# literal can only hold ASCII, so interpolating it into the source turns every
# candidate above 0x7f into a SyntaxError.
#
# PyGOST outputs digests in little-endian order, while the kernels expect them in
# big-endian; hence the digest[::-1] mirroring.

my $PY = <<'PYCODE';
import binascii
import sys
from pygost import gost34112012256
digest = gost34112012256.new (bytes.fromhex (sys.argv[1])).digest ()
print (binascii.hexlify (digest[::-1]).decode (), end = "")
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

  return _run (unpack ("H*", $word));
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed);

  return ($new_hash, $word);
}

1;
