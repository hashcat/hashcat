#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5  qw (md5 md5_hex);
use Digest::SHA  qw (sha1 sha1_hex);
use Digest::HMAC qw (hmac_hex);

sub module_constraints { [[8, 256], [24, 3000], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $pkt_num = shift // int (rand (100000000));
  my $engineID = shift // random_hex_string (26, 34);
  my $mode = shift // int (rand (1)) + 1;

  # make even if needed

  if (length ($salt) % 2 == 1)
  {
    $salt = $salt . "8";
  }

  my $string1 = $word x 1048576;

  $string1 = substr ($string1, 0, 1048576);

  my $digest1 = '';

  if ($mode eq 2)
  {
    $digest1 = sha1_hex ($string1);
  }
  elsif ($mode eq 1)
  {
    $digest1 = md5_hex ($string1);
  }

  my $buf = join '', $digest1, $engineID, $digest1;

  my $digest = '';

  if ($mode eq 2)
  {
    my $digest2 = sha1 (pack ("H*", $buf));

    $digest = hmac_hex (pack ("H*", $salt), $digest2, \&sha1);
  }
  elsif ($mode eq 1)
  {
    my $digest2 = md5 (pack ("H*", $buf));

    $digest = hmac_hex (pack ("H*", $salt), $digest2, \&md5);
  }

  $digest = substr ($digest, 0, 24);

  my $hash = sprintf ("\$SNMPv3\$0\$%s\$%s\$%s\$%s", $pkt_num, $salt, $engineID, $digest);

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
  return unless substr ($hash, 0, 10) eq '$SNMPv3$0$';

  my (undef, $signature, $version, $pkt_num, $salt, $engineID, $digest) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $pkt_num;
  return unless defined $salt;
  return unless defined $engineID;
  return unless defined $digest;

  my $word_packed = pack_if_HEX_notation ($word);

  # gen md5 & sha1 hashes

  my $new_hash_md5 = module_generate_hash ($word_packed, $salt, $pkt_num, $engineID, 1);
  my $new_hash_sha1 = module_generate_hash ($word_packed, $salt, $pkt_num, $engineID, 2);

  # parse digests

  my (undef, undef, undef, undef, undef, undef, $digest_md5) = split '\$', $new_hash_md5;
  my (undef, undef, undef, undef, undef, undef, $digest_sha1) = split '\$', $new_hash_sha1;

  if ($digest eq $digest_md5)
  {
    return ($new_hash_md5, $word);
  }
  else
  {
    return ($new_hash_sha1, $word);
  }
}

1;
