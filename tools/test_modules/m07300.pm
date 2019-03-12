#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::HMAC qw (hmac_hex);
use Digest::SHA  qw (sha1);

sub module_constraints { [[0, 256], [32, 256], [0, 55], [32, 32], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $hash_buf = hmac_hex ($salt, $word, \&sha1);

  my $hash = sprintf ("%s:%s", unpack ("H*", $salt), $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $salt = substr ($line, 0, $index1);

  $salt = pack ("H*", $salt);

  my $rest = substr ($line, $index1 + 1);

  my $index2 = index ($rest, ":");

  return if $index2 < 1;

  my $word = substr ($rest, $index2 + 1);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
