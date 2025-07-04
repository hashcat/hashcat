#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (hmac_sha256_hex);
use MIME::Base64 qw (encode_base64);
use JSON         qw (encode_json);

sub module_constraints { [[0, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift || get_random_mojolicious_salt ();

  my ($name, $value) = split('=', $salt);

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

  my $unpadded_cookie = $padded_cookie =~ s/Z*$//;

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
  my $payload_padded = $payload_json . 'Z' x (1025 - length $payload_json);
  my $payload_base64 = encode_base64 ($payload_padded, "");
  $payload_base64 =~ y/=/-/;

  return "mojolicious=$payload_base64";
}

sub get_signed_cookie
{
  my ($name, $value, $secret) = @_;
  my $sum = Digest::SHA::hmac_sha256_hex("$name=$value", $secret);
  return "$name=$value--$sum"
}

1;
