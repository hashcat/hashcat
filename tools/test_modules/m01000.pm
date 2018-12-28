#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD4 qw (md4_hex);
use Encode;

sub module_constraints { [[0, 255], [0, 0], [0, 27], [0, 0], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;

  my $digest = md4_hex (encode ('UTF-16LE', $word));

  return $digest;
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
