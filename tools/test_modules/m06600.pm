#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub get_random_agilekeychain_salt
{
  my $salt_buf = random_bytes (8);

  my $iv = random_bytes (16);

  my $prefix = "\x00" x 1008;

  my $ret = unpack ("H*", $salt_buf . $prefix . $iv);

  return $ret;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 1000;

  if (length $salt == 0)
  {
    $salt = get_random_agilekeychain_salt ();
  }

  my $salt_hex = substr ($salt, 0, 16);
  my $salt_bin = pack   ("H*", $salt_hex);

  my $prefix   = substr ($salt, 16, 2016);

  my $iv_hex   = substr ($salt, 2032);
  my $iv       = pack ("H*", $iv_hex);

  my $data = pack ("H*", "10101010101010101010101010101010");

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iter,
    output_len   => 16
  );

  my $key = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $cipher = Crypt::CBC->new ({
    key         => $key,
    cipher      => "Crypt::Rijndael",
    iv          => $iv,
    literal_key => 1,
    header      => "none",
    keysize     => 16
  });

  my $encrypted = unpack ("H*", $cipher->encrypt ($data));

  my $hash_buf = substr ($encrypted, 0, 32);

  my $hash = sprintf ("%i:%s:%s%s%s", $iter, $salt_hex, $prefix, $iv_hex, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $num_cols = () = $line =~ /:/g;

  return unless ($num_cols > 2);

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $iter = substr ($line, 0, $index1);

  my $index2 = index ($line, ":", $index1 + 1);

  return if $index2 < 1;

  my $salt = substr ($line, $index1 + 1, $index2 - $index1 - 1);

  $index1 = index ($line, ":", $index2 + 1);

  return if $index1 < 1;

  $salt .= substr ($line, $index2 + 1, $index1 - $index2 - 33);

  my $word = substr ($line, $index1 + 1);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
