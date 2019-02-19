#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha1);
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 40], [4, 15], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 1024;

  my $hash_buf = $salt;

  for (my $pos = 0; $pos < $iter; $pos++)
  {
    $hash_buf = sha1 ($word . $hash_buf);
  }

  $hash_buf = encode_base64 ($hash_buf . $salt, "");

  my $hash = sprintf ("{x-issha, %i}%s", $iter, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split (/:/, $line);

  return unless defined $hash_in;

  # SAP CODVN H (PWDSALTEDHASH) iSSHA-1
  return unless (substr ($hash_in, 0, 10) eq '{x-issha, ');

  # get iterations

  my $index1 = index ($hash_in, "}", 10);

  return if $index1 < 1;

  my $iter = substr ($hash_in, 10, $index1 - 10);

  $iter = int ($iter);

  # base64 substring

  my $base64_encoded = substr ($hash_in, $index1 + 1);
  my $base64_decoded = decode_base64 ($base64_encoded);

  my $salt = substr ($base64_decoded, 20);

  return unless defined $salt;
  return unless defined $iter;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
