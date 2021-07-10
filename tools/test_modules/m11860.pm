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

  my $python_code = <<"END_CODE";

import binascii
import hmac
import sys
from pygost import gost34112012512
key    = b"$salt"
msg    = b"$word"
digest = hmac.new (key, msg, gost34112012512).digest ()
print (binascii.hexlify (digest[::-1]).decode (), end = "")

END_CODE

  my $digest = `python3 -c '$python_code'`;

  my $hash = sprintf ("%s:%s", $digest, $salt);

  return $hash;
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
