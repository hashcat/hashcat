#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha1);
use Digest::HMAC qw (hmac);

sub module_constraints { [[0, 256], [8, 8], [0, 55], [8, 8], [-1, -1]] }

sub module_generate_hash
{
  my $word             = shift;
  my $salt             = shift;
  my $iterations       = shift // 20000;
  my $additional_param = shift;

  my $pbkdf1_salt = sprintf ('%s$sha1$%u', $salt, $iterations);

  my $tmp = hmac ($pbkdf1_salt, $word, \&sha1, 64);

  for (my $r = 1; $r < $iterations; $r++)
  {
    $tmp = hmac ($tmp, $word, \&sha1, 64);
  }

  my $digest = "";

  $digest .= to64 ((int (ord (substr ($tmp,  0, 1))) << 16) | (int (ord (substr ($tmp,  1, 1))) << 8) | (int (ord (substr ($tmp,  2, 1)))), 4);
  $digest .= to64 ((int (ord (substr ($tmp,  3, 1))) << 16) | (int (ord (substr ($tmp,  4, 1))) << 8) | (int (ord (substr ($tmp,  5, 1)))), 4);
  $digest .= to64 ((int (ord (substr ($tmp,  6, 1))) << 16) | (int (ord (substr ($tmp,  7, 1))) << 8) | (int (ord (substr ($tmp,  8, 1)))), 4);
  $digest .= to64 ((int (ord (substr ($tmp,  9, 1))) << 16) | (int (ord (substr ($tmp, 10, 1))) << 8) | (int (ord (substr ($tmp, 11, 1)))), 4);
  $digest .= to64 ((int (ord (substr ($tmp, 12, 1))) << 16) | (int (ord (substr ($tmp, 13, 1))) << 8) | (int (ord (substr ($tmp, 14, 1)))), 4);
  $digest .= to64 ((int (ord (substr ($tmp, 15, 1))) << 16) | (int (ord (substr ($tmp, 16, 1))) << 8) | (int (ord (substr ($tmp, 17, 1)))), 4);
  $digest .= to64 ((int (ord (substr ($tmp, 18, 1))) << 16) | (int (ord (substr ($tmp, 19, 1))) << 8) | 0                                 , 4);

  ## super hackish, but we have no other choice, as this byte is kind of a random byte added to the digest when the hash was created

  if (defined $additional_param)
  {
    $digest = substr ($digest, 0, 24) . substr ($additional_param, 24, 4);
  }

  my $hash = sprintf ("\$sha1\$%d\$%s\$%s", $iterations, $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 5;

  shift @data;

  my $signature = shift @data;

  return unless ($signature eq 'sha1');

  my $iterations       = shift @data;
  my $salt             = shift @data;
  my $additional_param = shift @data;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $additional_param);

  return ($new_hash, $word);
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
