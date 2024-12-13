#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha256_hex);
use MIME::Base64 qw (decode_base64 encode_base64);

sub module_constraints { [[0, 256], [0, 256], [0, 55], [0, 51], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  #$word = "hashcat";
  #$salt = decode_base64 ("c2FsdHNhbHQ=");

  my $salt_b64 = encode_base64 ($salt, "");

  my $digest = uc (sha256_hex ( uc (sha256_hex ($word)) . $salt));

  my $hash = sprintf ("%s:%s", $digest, $salt_b64);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $salt, $word) = split (':', $line);

  return unless defined $digest;
  return unless defined $salt;
  return unless defined $word;

  my $salt_b64 = decode_base64 ($salt);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt_b64);

  return ($new_hash, $word);
}

1;
