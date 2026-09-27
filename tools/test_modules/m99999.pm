#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[1, 55], [-1, -1], [1, 55], [-1, -1], [-1, -1]] }

# Plaintext (mode 99999): the hash string IS the plaintext (module_hash_decode
# stores the line verbatim and derives an MD4 digest from it). So the oracle is
# the identity function: emit the password as the hash. Single MD4 block caps
# the length at 55. Word length starts at 1, not 0: an empty word would produce
# an empty hash line, which test.sh's single-mode loop treats as end-of-input.

sub module_generate_hash
{
  my $word = shift;

  my $hash = sprintf ("%s", $word);

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
