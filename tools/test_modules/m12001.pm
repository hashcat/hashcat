#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (encode_base64 decode_base64);
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
    iterations => 10000,
    output_len => 32
  );

  my $base64 = encode_base64 ($salt . $pbkdf2->PBKDF2 ($salt, $word), "");

  my $hash = sprintf ("{PKCS5S2}%s", $base64);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split ":", $line;

  return unless defined $digest;
  return unless defined $word;

  my $signature = substr ($digest, 0, 9);

  return unless ($signature eq '{PKCS5S2}');

  my $hash = substr ($digest, 9);

  # base64 buf

  my $base64_decoded = decode_base64 ($hash);

  return if (length ($base64_decoded) != (16 + 32));

  my $salt = substr ($base64_decoded, 0, 16);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
