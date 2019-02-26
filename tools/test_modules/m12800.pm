#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::MD4 qw (md4_hex);
use Encode;

sub module_constraints { [[0, 256], [20, 20], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 100;

  my $nt = md4_hex (encode ("UTF-16LE", $word));

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => 32
  );

  my $salt_buf_bin = pack ("H*", $salt);

  my $tmp = $pbkdf2->PBKDF2 ($salt_buf_bin, uc (encode ("UTF-16LE", $nt)));

  my $hash = sprintf ("v1;PPH1_MD4,%s,%d,%s", $salt, $iter, unpack ("H*", $tmp));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;

  my @data = split /\,/, $hash_in;

  return unless scalar @data == 4;

  return unless (shift @data eq 'v1;PPH1_MD4');

  my $salt = shift @data;
  my $iter = shift @data;

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
