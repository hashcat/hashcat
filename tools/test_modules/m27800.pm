#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MurmurHash3 qw (murmur32);

sub module_constraints { [[-1, -1], [-1, -1], [0, 31], [8, 8], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $seed = unpack ("I>", pack ("H*", $salt));

  my $digest = murmur32 ($word, $seed);

  $digest = unpack ("H*", pack ("I>", $digest));

  my $hash = sprintf ("%s:%s", $digest, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $seed, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $seed;
  return unless defined $word;

  return unless ($hash =~ m/^[0-9a-fA-F]{8}$/);
  return unless ($seed =~ m/^[0-9a-fA-F]{8}$/);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $seed);

  return ($new_hash, $word);
}

1;
