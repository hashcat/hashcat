#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  my $iterations = 64;

  if (length ($iter))
  {
    $iterations = 1 << int ($iter);
  }

  my $digest = aix_ssha256_pbkdf2 ($word, $salt, $iterations);

  return sprintf ("{ssha256}%02i\$%s\$%s", log ($iterations) / log (2), $salt, $digest);
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $signature = substr ($hash, 0, 9);

  return unless ($signature eq "{ssha256}");

  $hash = substr ($hash, 9);

  my @data = split ('\$', $hash);

  return unless scalar @data == 3;

  my $iter   = shift (@data);
  my $salt   = shift @data;
  my $digest = shift @data;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

sub aix_ssha256_pbkdf2
{
  my $word_buf   = shift;
  my $salt_buf   = shift;
  my $iterations = shift;

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256);

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iterations,
    output_len   => 32
  );

  my $hash_buf = $pbkdf2->PBKDF2 ($salt_buf, $word_buf);

  my $tmp_hash = "";

  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  0, 1))) << 16) | (int (ord (substr ($hash_buf,  1, 1))) << 8) | (int (ord (substr ($hash_buf,  2, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  3, 1))) << 16) | (int (ord (substr ($hash_buf,  4, 1))) << 8) | (int (ord (substr ($hash_buf,  5, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  6, 1))) << 16) | (int (ord (substr ($hash_buf,  7, 1))) << 8) | (int (ord (substr ($hash_buf,  8, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  9, 1))) << 16) | (int (ord (substr ($hash_buf, 10, 1))) << 8) | (int (ord (substr ($hash_buf, 11, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 12, 1))) << 16) | (int (ord (substr ($hash_buf, 13, 1))) << 8) | (int (ord (substr ($hash_buf, 14, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 15, 1))) << 16) | (int (ord (substr ($hash_buf, 16, 1))) << 8) | (int (ord (substr ($hash_buf, 17, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 18, 1))) << 16) | (int (ord (substr ($hash_buf, 19, 1))) << 8) | (int (ord (substr ($hash_buf, 20, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 21, 1))) << 16) | (int (ord (substr ($hash_buf, 22, 1))) << 8) | (int (ord (substr ($hash_buf, 23, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 24, 1))) << 16) | (int (ord (substr ($hash_buf, 25, 1))) << 8) | (int (ord (substr ($hash_buf, 26, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 27, 1))) << 16) | (int (ord (substr ($hash_buf, 28, 1))) << 8) | (int (ord (substr ($hash_buf, 29, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 30, 1))) << 16) | (int (ord (substr ($hash_buf, 31, 1))) << 8)                                          , 3);

  return $tmp_hash;
}

sub to64
{
  my $v = shift;
  my $n = shift;

  my $itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  my $ret = "";

  while (($n - 1) >= 0)
  {
    $n = $n - 1;

    $ret .= substr ($itoa64, $v & 0x3f, 1);

    $v = $v >> 6;
  }

  return $ret
}

1;
