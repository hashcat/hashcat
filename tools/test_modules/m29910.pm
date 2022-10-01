#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Mode::ECB;
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $iv    = shift // random_hex_string (16);
  my $ct    = shift;
  my $iter  = shift // 100000;

  # pbkdf2 part

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => 16
  );

  my $salt_bin = pack ("H*", $salt);

  my $key = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $aes = Crypt::Mode::ECB->new ('AES', 0);

  my $iv_bin = pack ("H*", $iv);

  my $ctr_len = 16;

  my $ctr;

  for (my $i = 0, my $counter = 1; $i < ($ctr_len >> 4); $i++, $counter++)
  {
    my $tmp_iv = $iv_bin . pack ("Q>", $counter);

    $tmp_iv = $aes->encrypt ($tmp_iv, $key);

    $ctr .= $tmp_iv;
  }

  my $pt_bin;

  if (defined $ct)
  {
    my $ct_bin = pack ("H*", $ct);

    $pt_bin = xor_len (substr ($ctr, 4, 4), $ct_bin, 4);

    if ($pt_bin eq "\xd2\xc3\xb4\xa1")
    {
      # ok
    }
    else
    {
      $pt_bin = "\xff\xff\xff\xff";
    }
  }
  else
  {
    $pt_bin = "\xd2\xc3\xb4\xa1";
  }

  my $ct_bin = xor_len (substr ($ctr, 4, 4), $pt_bin, 4);

  my $hash = sprintf ('$encdv-pbkdf2$1$1$%s$%s$32$%s$%d', unpack ("H*", $iv_bin), unpack ("H*", $ct_bin), unpack ("H*", $salt_bin), $iter);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 14) eq '$encdv-pbkdf2$';

  my (undef, $signature, $version, $algo_id, $iv, $ct, $salt_len, $salt, $iter) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $algo_id;
  return unless defined $iv;
  return unless defined $ct;
  return unless defined $salt_len;
  return unless defined $salt;
  return unless defined $iter;

  return unless ($version == 1);
  return unless ($algo_id == 1);
  return unless ($salt_len == 32);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iv, $ct, $iter);

  return ($new_hash, $word);
}

sub xor_len
{
  my $in1 = shift;
  my $in2 = shift;
  my $len = shift;

  my $out;

  for (my $i = 0; $i < $len; $i++)
  {
    $out .= chr (ord (substr ($in1, $i, 1)) ^ ord (substr ($in2, $i, 1)));
  }

  return $out;
}

1;
