#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha384 sha384_hex hmac_sha384_hex);

sub module_constraints { [[8, 256], [64, 3000], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $pkt_num = shift // int (rand (100000000));
  my $engineID = shift // random_hex_string (26, 34);

  # padding engineID: fill with zero

  my $pad_len = 34 - length ($engineID);

  my $engineID_orig = $engineID;

  $engineID = join '', $engineID, "0" x $pad_len;

  # make salt even if needed

  if (length ($salt) % 2 == 1)
  {
    $salt = $salt . "8";
  }

  my $string1 = $word x 1048576;

  $string1 = substr ($string1, 0, 1048576);

  my $sha384_digest1 = sha384_hex ($string1);

  my $buf = join '', $sha384_digest1, $engineID, $sha384_digest1;

  my $sha384_digest2 = sha384 (pack ("H*", $buf));

  my $digest = hmac_sha384_hex (pack ("H*", $salt), $sha384_digest2);

  $digest = substr ($digest, 0, 64);

  my $hash = "\$SNMPv3\$5\$" . $pkt_num . "\$" . $salt . "\$" . $engineID_orig . "\$" . $digest;

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
  return unless substr ($hash, 0, 10) eq '$SNMPv3$5$';

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
