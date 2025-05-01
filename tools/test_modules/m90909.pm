#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha256 sha384 sha512);
use Digest::HMAC qw (hmac);
use MIME::Base64 qw (encode_base64url decode_base64url);
use JSON         qw (encode_json decode_json);

sub module_constraints { [[0, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift || get_random_express_salt ();

  my ($header_base64, $payload) = split (/\./, $salt);

  my $header_express = decode_base64url ($header_base64);

  my $header = decode_json ($header_express);

  my $alg = $header->{"alg"};

  my $digest;

  if ($alg eq "HS256")
  {
    $digest = hmac ($payload, $word, \&sha256, 64);
  }
  elsif ($alg eq "HS384")
  {
    $digest = hmac ($payload, $word, \&sha384, 128);
  }
  elsif ($alg eq "HS512")
  {
    $digest = hmac ($payload, $word, \&sha512, 128);
  }
  else
  {
    die "not supported hash\n";
  }

  my $hash = sprintf("%s\$%s", $payload, encode_base64url($digest));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split (/\$/, $hash);

  return unless scalar @data == 2;

  my ($salt, $signature) = @data;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

sub get_random_express_salt
{
    my @hashes =
  (
    "HS256",
    "HS384", 
    "HS512", 
  );

  my $rnd = random_number (0, scalar @hashes - 1);

  my $hash = $hashes[$rnd];

  my $header =
  {
    "alg" => $hash
  };

  my $random_key = random_number (1, 100000000);
  my $random_val = random_number (1, 100000000);

  my $payload =
  {
    $random_key => $random_val
  };

  my $header_json    = encode_json ($header);
  my $header_base64  = encode_base64url ($header_json, "");

  my $cookie         = "session";
  my $payload_json   = encode_json ($payload);

  my $payload_base64 = encode_base64url ($payload_json, "");

  return $header_base64 . "." . $cookie . "=" . $payload_base64;
}

1;
