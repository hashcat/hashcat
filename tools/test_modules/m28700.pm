#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha256);
use Digest::HMAC qw (hmac hmac_hex);

sub module_constraints { [[0, 252], [8, 8], [0, 51], [8, 8], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift; # date
  my $region = shift // "us-east-1";
  my $service = shift // "s3";
  my $canonical = shift // random_hex_string (64);

  my $date = 0;
  my $longdate = 0;

  if (length ($salt) == 8)
  {
    $date = $salt;
    $longdate = sprintf ("%sT000000Z", $date);
  }

  if (length ($salt) == 16)
  {
    $longdate = $salt;
    $date = substr ($salt, 0, 8);
  }

  my $kPassKey = sprintf ("AWS4%s", $word);

  my $kDate = hmac ($date, $kPassKey, \&sha256, 64);
  my $kRegion = hmac ($region, $kDate, \&sha256, 64);
  my $kService = hmac ($service, $kRegion, \&sha256, 64);
  my $kSigning = hmac ("aws4_request", $kService, \&sha256, 64);

  my $stringtosign = sprintf ("AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s", $longdate, $date, $region, $service, $canonical);

  my $digest = hmac_hex ($stringtosign, $kSigning, \&sha256, 64);

  my $hash = sprintf ("\$AWS-Sig-v4\$0\$%s\$%s\$%s\$%s\$%s", $longdate, $region, $service, $canonical, $digest);

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
  return unless substr ($hash, 0, 14) eq '$AWS-Sig-v4$0$';

  my (undef, $signature, $version, $salt, $region, $service, $canonical, $digest) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $salt; # date
  return unless defined $region;
  return unless defined $service;
  return unless defined $canonical;
  return unless defined $digest;

  return unless length ($salt) == 16;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $region, $service, $canonical);

  return ($new_hash, $word);
}

1;
