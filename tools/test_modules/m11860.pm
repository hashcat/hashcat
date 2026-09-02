#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

# The password goes over argv as hex. It is arbitrary bytes, and a Python b"..."
# literal can only hold ASCII, so interpolating it into the source turns every
# candidate above 0x7f into a SyntaxError.

my $PY = <<'PYCODE';
import binascii
import hmac
import sys
from pygost import gost34112012512
key    = bytes.fromhex (sys.argv[2])
msg    = bytes.fromhex (sys.argv[1])
digest = hmac.new (key, msg, gost34112012512).digest ()
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
  my $salt = shift;

  my $digest = _run (unpack ("H*", $word), unpack ("H*", $salt));

  return unless defined $digest;

  return sprintf ("%s:%s", $digest, $salt);
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
