#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

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

sub aix_ssha1_pbkdf2
{
  my $word_buf   = shift;
  my $salt_buf   = shift;
  my $iterations = shift;

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iterations,
  );

  my $hash_buf = $pbkdf2->PBKDF2 ($salt_buf, $word_buf);

  my $tmp_hash = "";

  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  0, 1))) << 16) | (int (ord (substr ($hash_buf,  1, 1))) << 8) | (int (ord (substr ($hash_buf,  2, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  3, 1))) << 16) | (int (ord (substr ($hash_buf,  4, 1))) << 8) | (int (ord (substr ($hash_buf,  5, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  6, 1))) << 16) | (int (ord (substr ($hash_buf,  7, 1))) << 8) | (int (ord (substr ($hash_buf,  8, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  9, 1))) << 16) | (int (ord (substr ($hash_buf, 10, 1))) << 8) | (int (ord (substr ($hash_buf, 11, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 12, 1))) << 16) | (int (ord (substr ($hash_buf, 13, 1))) << 8) | (int (ord (substr ($hash_buf, 14, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 15, 1))) << 16) | (int (ord (substr ($hash_buf, 16, 1))) << 8) | (int (ord (substr ($hash_buf, 17, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 18, 1))) << 16) | (int (ord (substr ($hash_buf, 19, 1))) << 8)                                          , 3);

  return $tmp_hash;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 64;

  my $hash_buf = aix_ssha1_pbkdf2 ($word, $salt, $iter);

  my $hash = sprintf ("{ssha1}%02i\$%s\$%s", log ($iter) / log (2), $salt, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");
  my $hash_in = substr ($line, 0, $index1);

  return if $index1 < 1;

  my $word = substr ($line, $index1 + 1);

  my $index2 =  index ($hash_in, "}");
  my $index3 =  index ($hash_in, "\$");
  my $index4 = rindex ($hash_in, "\$");

  my $salt = substr ($hash_in, $index3 + 1, $index4 - $index3 - 1);

  my $iter = substr ($hash_in, $index2 + 1, $index3 - $index2 - 1);

  return unless defined $salt;
  return unless defined $word;
  return unless defined $iter;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, 1 << int ($iter));

  return ($new_hash, $word);
}

1;
