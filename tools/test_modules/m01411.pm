#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha256_hex);
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [0, 256], [0, 55], [0, 55], [0, 55]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = sha256_hex ($word . $salt);

  my $base64_buf = encode_base64 (pack ("H*", $digest) . $salt, "");

  my $hash = sprintf ("{SSHA256}%s", $base64_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $signature    = substr ($hash, 0, 9);
  my $plain_base64 = substr ($hash, 9);

  return unless ($signature eq "{SSHA256}"); 
  return unless defined $plain_base64;

  # base64 decode to extract salt
  my $decoded = decode_base64 ($plain_base64);

  my $salt = substr ($decoded, 32);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
