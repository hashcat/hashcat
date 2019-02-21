#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::DES;

sub module_constraints { [[24, 24], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $word1 = substr ($word,  0, 8);
  my $word2 = substr ($word,  8, 8);
  my $word3 = substr ($word, 16, 8);

  my $cipher1 = new Crypt::DES ($word1);
  my $cipher2 = new Crypt::DES ($word2);
  my $cipher3 = new Crypt::DES ($word3);

  my $pt1_bin = pack ("H*", $salt);

  my $ct1_bin = $cipher1->encrypt ($pt1_bin);
  my $ct2_bin = $cipher2->decrypt ($ct1_bin);
  my $ct3_bin = $cipher3->encrypt ($ct2_bin);

  my $hash = sprintf ("%s:%s", unpack ("H*", $ct3_bin), $salt);

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
