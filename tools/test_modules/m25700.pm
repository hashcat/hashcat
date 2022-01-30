#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[-1, -1], [-1, -1], [0, 55], [8, 8], [-1, -1]] }

sub MurmurHash
{
  use integer;

  my $word = shift;
  my $seed = shift;

  # https://tanjent.livejournal.com/756623.html

  my $m = 0x7fd652ad;
  my $r = 16;

  my $hash = $seed;

  $hash += 0xdeadbeef;

  my @chars = unpack ("c*", $word);

  my $len = length $word;

  my $i;

  for ($i = 0; $i < $len - 3; $i += 4)
  {
    my $c0 = $chars[$i + 0];
    my $c1 = $chars[$i + 1];
    my $c2 = $chars[$i + 2];
    my $c3 = $chars[$i + 3];

    my $l = ($c0 <<  0)
          | ($c1 <<  8)
          | ($c2 << 16)
          | ($c3 << 24);

    $hash += $l;
    $hash *= $m;
    $hash ^= ($hash & 0xffffffff) >> $r;
  }

  my $rem = $len & 3;

  if ($rem == 3)
  {
    my $c0 = $chars[$i + 0];
    my $c1 = $chars[$i + 1];
    my $c2 = $chars[$i + 2];
    my $c3 = 0;

    my $l = ($c0 <<  0)
          | ($c1 <<  8)
          | ($c2 << 16)
          | ($c3 << 24);

    $hash += $l;
    $hash *= $m;
    $hash ^= ($hash & 0xffffffff) >> $r;
  }
  elsif ($rem == 2)
  {
    my $c0 = $chars[$i + 0];
    my $c1 = $chars[$i + 1];
    my $c2 = 0;
    my $c3 = 0;

    my $l = ($c0 <<  0)
          | ($c1 <<  8)
          | ($c2 << 16)
          | ($c3 << 24);

    $hash += $l;
    $hash *= $m;
    $hash ^= ($hash & 0xffffffff) >> $r;
  }
  elsif ($rem == 1)
  {
    my $c0 = $chars[$i + 0];
    my $c1 = 0;
    my $c2 = 0;
    my $c3 = 0;

    my $l = ($c0 <<  0)
          | ($c1 <<  8)
          | ($c2 << 16)
          | ($c3 << 24);

    $hash += $l;
    $hash *= $m;
    $hash ^= ($hash & 0xffffffff) >> $r;
  }

  $hash *= $m;
  $hash ^= ($hash & 0xffffffff) >> 10;
  $hash *= $m;
  $hash ^= ($hash & 0xffffffff) >> 17;

  return $hash & 0xffffffff;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $salt_bin = pack ("H*", $salt);

  my $seed = unpack ("N", $salt_bin); # or maybe "L" ? not enought example data to clarify

  my $digest = MurmurHash ($word, $seed);

  my $hash = sprintf ("%08x:%08x", $digest, $seed);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;
  return unless defined $salt;

  return unless length $hash == 8;
  return unless length $salt == 8;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
