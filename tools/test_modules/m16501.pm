#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::HMAC qw (hmac);
use MIME::Base64 qw (encode_base64url);
use JSON         qw (encode_json);

sub module_constraints { [[0, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift || get_random_mojolicious_salt ();

  ## mojolicious=eyJleHBpcmVzIjoxMTEyNDcwNjIwLCJuZXdfZmxhc2giOnsibWVzc2FnZSI6IkhlbGxvIHRoZXJlLiJ9LCJ1c2VyIjoiYWxpY2UifQ
  my ($name, $value) = split('=', $salt);

  ## example is 102 chars in length, 1025-102 = so it gets 923 chars of "Z" padding, "--" separator and HMAC-SHA256 signature
  ## mojolicious=eyJleHBpcmVzIjoxMTEyNDcwNjIwLCJuZXdfZmxhc2giOnsibWVzc2FnZSI6IkhlbGxvIHRoZXJlLiJ9LCJ1c2VyIjoiYWxpY2UifQZZZZZZZ(...)ZZZZZZ--1bf346f55562ac2a08d1b86a28e87bf5aad357d7a92e816567271f5b420b93c1
  my $hash = get_signed_cookie ($name, $value, $word);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split (/--/, $hash);

  return unless scalar @data == 2;

  my ($padded_cookie, $signature) = @data;

  my $unpadded_cookie = $padded_cookie =~ s/\}\KZ*$//r;

  my ($cookie_name, $cookie_value) = split('=', $unpadded_cookie);

  my $salt = $cookie_name . "=" . $cookie_value;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

sub get_random_mojolicious_salt
{
  my $random_key = random_number (1, 100000000);
  my $random_val = random_number (1, 100000000);

  my $payload =
  {
    $random_key => $random_val
  };

  my $payload_json   = encode_json ($payload);

  my $payload_base64 = encode_base64url ($payload_json, "");

  return "mojolicious=$payload_base64";
}

sub get_signed_cookie
{
  my ($name, $value, $secret) = @_;

  sub add_mojolicious_padding {
    return $_[0] . 'Z' x (1025 - length $_[0]);
  }

  my $padded = add_mojolicious_padding $value;

  my $sum = Digest::SHA::hmac_sha256_hex("$name=$padded", $secret);
  return "$name=$padded--$sum"
}

1;
