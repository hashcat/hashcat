#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 255], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub djb32
{
  my $word = shift;

  my @chars = unpack ("C*", $word);

  my $hash = 0;

  while (my $c = shift @chars)
  {
    $hash = ($hash * 31) & 0xffffffff;
    $hash = ($hash + $c) & 0xffffffff;
  }

  return $hash;
}

sub module_generate_hash
{
  my $word = shift;

  my $digest = djb32 ($word);

  my $hash = sprintf ("%08x", $digest);

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
