#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha1);

sub module_constraints { [[0, 256], [1, 16], [0, 13], [16, 16], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = androidpin_hash ($word, $salt);

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

sub androidpin_hash
{
  my $word = shift;
  my $salt = shift;

  my $w = sprintf ("%d%s%s", 0, $word, $salt);

  my $digest = sha1 ($w);

  for (my $i = 1; $i < 1024; $i++)
  {
    $w = $digest . sprintf ("%d%s%s", $i, $word, $salt);

    $digest = sha1 ($w);
  }

  my ($A, $B, $C, $D, $E) = unpack ("N5", $digest);

  return sprintf ("%08x%08x%08x%08x%08x", $A, $B, $C, $D, $E);
}

1;
