#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5  qw (md5);
use Digest::HMAC qw (hmac_hex);
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [0, 127], [0, 55], [0, 55], [-1, -1]] }

sub module_generate_hash
{
  my $word     = shift;
  my $salt     = shift;
  my $username = shift // "user";

  my $challengeb64 = encode_base64 ($salt, "");

  my $hash_buf = hmac_hex ($salt, $word, \&md5);

  my $responseb64 = encode_base64 ($username . " " . $hash_buf, "");

  my $hash = sprintf ('$cram_md5$%s$%s', $challengeb64, $responseb64);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Cram MD5
  return unless (substr ($line, 0, 10) eq '$cram_md5$');

  # get hash
  my $index1 = index ($line, "\$", 10);

  return if $index1 < 1;

  # challenge

  my $challengeb64 = substr ($line, 10,  $index1 - 10);

  my $salt = decode_base64 ($challengeb64);

  # response

  my $index2 = index ($line, ":", $index1 + 1);

  return if $index2 < 1;

  my $responseb64 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

  my $response = decode_base64 ($responseb64);

  my $param = substr ($response, 0, length ($response) - 32 - 1); # -1 is for space

  my $word = substr ($line, $index2 + 1);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $param);

  return ($new_hash, $word);
}

1;
