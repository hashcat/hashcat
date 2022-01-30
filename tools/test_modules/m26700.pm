#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha224 sha224_hex);
use Digest::HMAC qw (hmac_hex);

sub module_constraints { [[8, 256], [32, 3000], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $pkt_num = shift // int (rand (100000000));
  my $engineID = shift // random_hex_string (26, 34);

  # make even if needed

  if (length ($salt) % 2 == 1)
  {
    $salt = $salt . "8";
  }

  my $string1 = $word x 1048576;

  $string1 = substr ($string1, 0, 1048576);

  my $sha224_digest1 = sha224_hex ($string1);

  my $buf = join '', $sha224_digest1, $engineID, $sha224_digest1;

  my $sha224_digest2 = sha224 (pack ("H*", $buf));

  my $digest = hmac_hex (pack ("H*", $salt), $sha224_digest2, \&sha224);

  $digest = substr ($digest, 0, 32);

  my $hash = sprintf ("\$SNMPv3\$3\$%s\$%s\$%s\$%s", $pkt_num, $salt, $engineID, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless length ($word) gt 0;
  return unless substr ($hash, 0, 10) eq '$SNMPv3$3$';

  my (undef, $signature, $version, $pkt_num, $salt, $engineID, $digest) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $pkt_num;
  return unless defined $salt;
  return unless defined $engineID;
  return unless defined $digest;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $pkt_num, $engineID);

  return ($new_hash, $word);
}

1;
