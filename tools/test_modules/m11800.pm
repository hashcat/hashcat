#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;

  my $python_code = <<"END_CODE";

import binascii
import sys
from pygost import gost34112012512
digest = gost34112012512.new(b"$word").digest()
sys.stdout.write(binascii.hexlify(digest[::-1]))

END_CODE

  my $hash = `python2 -c '$python_code'`;

  return $hash;
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
