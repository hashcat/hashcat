#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::CRC qw (crc32);

sub module_constraints { [[-1, -1], [-1, -1], [0, 31], [8, 8], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;

  my $digest = crc32 ($word);

  my $hash = sprintf ("%08x:00000000", $digest);

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
