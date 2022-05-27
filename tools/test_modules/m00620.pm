#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::BLAKE2 qw (blake2b_hex);

sub module_constraints { [[0, 127], [0, 127], [0, 55], [0, 55], [0, 55]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = blake2b_hex ($salt . $word);

  my $hash = sprintf ("\$BLAKE2\$%s:%s", lc ($digest), $salt);

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
