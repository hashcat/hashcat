#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha1);
use Digest::HMAC qw (hmac_hex);

sub module_constraints { [[0, 256], [8, 12], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $padded_time = sprintf ("%016x", int (int ($salt) / 30));
  my $data = pack ('H*', $padded_time);
  my $key = $word;

  my $digest = hmac_hex ($data, $key, \&sha1, 64);

  my $offset = hex (substr ($digest, -8)) & 0xf;
  $offset *= 2;

  my $token = hex (substr ($digest, $offset, 8));
  $token &= 0x7fffffff;
  $token %= 1000000;

  # token must be leading zero padded, and salt leading zero stripped
  my $hash = sprintf ("%06d:%d", $token, int ($salt));

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
