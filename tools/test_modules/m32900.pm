#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1);
use MIME::Base64 qw (encode_base64);
use MIME::Base64 qw (decode_base64);

sub module_constraints { [[0, 256], [4, 100], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 1000;
  my $verify_mode = shift // 0;

  my $salt_decoded = "";

  # Check if called through module_verify_hash
  if ($verify_mode == 1)
  {
    $salt_decoded = decode_base64($salt);
  }
  else
  {
    $salt_decoded = $salt;
  }

  my $digest = $word . $salt_decoded;

  for (my $i = 1 ; $i <= $iter ; $i++)
  {
    $digest = sha1 ($digest);
  }

  my $hash_buf = encode_base64 ($digest, "");

  my $salt_buf = encode_base64 ($salt_decoded, "");
  
  my $hash = sprintf ("PBKDF1:sha1:%i:%s:%s", $iter, $salt_buf, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;
  
  my ($signature, $primitive, $iter, $salt, $hash, $word) = split (':', $line);

  return unless defined $signature;
  return unless defined $primitive;
  return unless defined $iter;
  return unless defined $salt;
  return unless defined $hash;
  return unless defined $word;

  return unless ($signature eq 'PBKDF1');
  return unless ($primitive eq 'sha1');

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter, 1);

  return ($new_hash, $word);
}

1;
