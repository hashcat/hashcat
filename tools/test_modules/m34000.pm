#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64  qw (decode_base64 encode_base64);
use Crypt::Argon2 qw (argon2_raw);

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $sign  = shift // ("argon2d","argon2i","argon2id")[random_number (0, 2)];
  my $m     = shift // 65536;
  my $t     = shift // 3;
  my $p     = shift // 1;
  my $len   = shift // random_number (1, 2) * 16;

  my $salt_bin = pack ("H*", $salt);

  my $digest_bin = argon2_raw ($sign, $word, $salt_bin, $t, $m . "k", $p, $len);

  my $salt_base64   = encode_base64 ($salt_bin,   ""); $salt_base64   =~ s/=+$//;
  my $digest_base64 = encode_base64 ($digest_bin, ""); $digest_base64 =~ s/=+$//;

  my $hash = sprintf ('$%s$v=19$m=%d,t=%d,p=%d$%s$%s', $sign, $m, $t, $p, $salt_base64, $digest_base64);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless ((substr ($hash, 0,  9) eq '$argon2d$')
              || (substr ($hash, 0,  9) eq '$argon2i$')
              || (substr ($hash, 0, 10) eq '$argon2id$'));              

  my (undef, $signature, $version, $config, $salt, $digest) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $config;
  return unless defined $salt;
  return unless defined $digest;

  my ($m_config, $t_config, $p_config) = split ("\,", $config);

  return unless ($version eq "v=19");

  my $m = (split ("=", $m_config))[1];
  my $t = (split ("=", $t_config))[1];
  my $p = (split ("=", $p_config))[1];

  $salt   = decode_base64 ($salt);
  $digest = decode_base64 ($digest);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, unpack ("H*", $salt), $signature, $m, $t, $p, length ($digest));

  return ($new_hash, $word);
}

1;
