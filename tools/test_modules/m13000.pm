#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 15;
  my $iv   = shift // "0" x 32;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => (1 << $iter) + 32,
    output_len => 32
  );

  my $salt_bin = pack ("H*", $salt);

  my $hash = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $hash_final = substr ($hash,  0, 8)
                 ^ substr ($hash,  8, 8)
                 ^ substr ($hash, 16, 8)
                 ^ substr ($hash, 24, 8);

  my $tmp_hash = sprintf ('$rar5$16$%s$%d$%s$8$%s', $salt, $iter, $iv, unpack ("H*", $hash_final));

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 8;

  shift @data;

  my $signature    = shift @data;
  my $salt_len     = shift @data;
  my $salt_buf     = shift @data;
  my $iterations   = shift @data;
  my $iv           = shift @data;
  my $pswcheck_len = shift @data;
  my $pswcheck     = shift @data;

  return unless ($signature eq "rar5");
  return unless ($salt_len == 16);
  return unless ($pswcheck_len == 8);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt_buf, $iterations, $iv);

  return ($new_hash, $word);
}

1;
