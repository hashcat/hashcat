#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha512 sha512_hex hmac_sha512_hex);

sub module_constraints { [[8, 256], [96, 3000], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $pkt_num = shift // int (rand (100000000));
  my $engineID = shift // random_hex_string (26, 34);

  # padding engineID: fill with zero

  my $pad_len = 34 - length ($engineID);

  $engineID = join '', $engineID, "0" x $pad_len;

  # make salt even if needed

  if (length ($salt) % 2 == 1)
  {
    $salt = $salt . "8";
  }

  my $string1 = $word x 1048576;

  $string1 = substr ($string1, 0, 1048576);

  my $sha512_digest1 = sha512_hex ($string1);

  my $buf = join '', $sha512_digest1, $engineID, $sha512_digest1;

  my $sha512_digest2 = sha512 (pack ("H*", $buf));

  my $digest = hmac_sha512_hex (pack ("H*", $salt), $sha512_digest2);

  $digest = substr ($digest, 0, 96);

  my $hash = "\$SNMPv3\$6\$" . $pkt_num . "\$" . $salt . "\$" . $engineID . "\$" . $digest;

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
  return unless substr ($hash, 0, 10) eq '$SNMPv3$6$';

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
