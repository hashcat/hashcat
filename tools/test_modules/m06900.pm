#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::GOST qw (gost_hex);

sub module_constraints { [[-1, -1], [-1, -1], [1, 32], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;

  my $digest = gost_hex ($word);

  my $hash = sprintf ("%s", $digest);

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
