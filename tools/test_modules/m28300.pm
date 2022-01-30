#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA1 qw (sha1);
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [224, 224], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $salt_bin = pack ("H*", $salt);

  my $s1 = sha1 ($word);
  my $s2 = encode_base64 ($s1, "")
         . encode_base64 ($salt_bin, "");
  my $s3 = sha1 ($s2);

  my $hash = sprintf ('$teamspeak$3$%s$%s', encode_base64 ($s3, ""), encode_base64 ($salt_bin, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my (undef, $signature, $version, $digest, $salt) = split ('\$', $hash);

  return unless defined $signature;
  return unless defined $version;
  return unless defined $digest;
  return unless defined $salt;

  $salt = decode_base64 ($salt);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, unpack ("H*", $salt));

  return ($new_hash, $word);
}

1;
