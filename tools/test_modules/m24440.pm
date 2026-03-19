#!/usr/bin/env perl

##
## Author......: kozmer
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256 hmac_sha256);
use Encode;

sub module_constraints { [[0, 48], [16, 40], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 2048;
  my $data = shift;

  my $salt_bin = pack ("H*", $salt);

  if (defined ($data) == 0)
  {
    $data = unpack ("H*", random_bytes (100));
  }

  my $data_bin = pack ("H*", $data);

  # PKCS#12 KDF (RFC 7292 Appendix B), id=3 (MAC key)

  my $pwd_utf16 = encode ("UTF-16BE", $word) . "\x00\x00";
  my $p = length ($pwd_utf16);

  my $D = "\x03" x 64;

  my $v = 64;
  my $S = "";

  if (length ($salt_bin) > 0)
  {
    my $s_repeats = int ($v / length ($salt_bin)) + 1;
    $S = substr ($salt_bin x $s_repeats, 0, $v);
  }

  my $v2 = int (($p + $v - 1) / $v) * $v;
  my $P = "";

  if ($p > 0)
  {
    my $p_repeats = int ($v2 / $p) + 1;
    $P = substr ($pwd_utf16 x $p_repeats, 0, $v2);
  }

  my $h = sha256 ($D . $S . $P);

  for (my $i = 1; $i < $iter; $i++)
  {
    $h = sha256 ($h);
  }

  my $mac_key = substr ($h, 0, 32);

  my $computed_mac = hmac_sha256 ($data_bin, $mac_key);

  my $hash = sprintf ('$pkcs12$256$%d$%d$%s$%d$%s$%s',
    $iter,
    length ($salt_bin),
    unpack ("H*", $salt_bin),
    length ($data_bin),
    $data,
    unpack ("H*", $computed_mac));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 10) eq '$pkcs12$2';

  my (undef, $signature, $mac_algo, $iter, $salt_len, $salt, $data_len, $data, $mac) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $mac_algo;
  return unless defined $iter;
  return unless defined $salt_len;
  return unless defined $salt;
  return unless defined $data_len;
  return unless defined $data;
  return unless defined $mac;

  return unless ($signature eq 'pkcs12');
  return unless ($mac_algo eq '256');

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter, $data);

  return ($new_hash, $word);
}

1;
