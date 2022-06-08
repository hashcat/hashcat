#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha1);
use Digest::HMAC qw (hmac);
use MIME::Base64 qw (encode_base64url);
use JSON         qw (encode_json);

sub module_constraints { [[0, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift || get_random_flask_salt ();

  # https://github.com/hashcat/hashcat/issues/3239
  #first = HMACSHA1(key=secret, message="cookie-session").digest() // "cookie-session" is a constant; digest is raw digest bytes
  #second = HMACSHA1(key=first, message=message).digest()

  my $digest1 = hmac ("cookie-session", $word, \&sha1);

  my $digest2 = hmac ($salt, $digest1, \&sha1);

  my $hash = sprintf ("%s.%s", $salt, encode_base64url ($digest2, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split (/\./, $hash);

  return unless scalar @data == 3;

  my ($header, $payload, $signature) = @data;

  my $salt = $header . "." . $payload;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

sub get_random_flask_salt
{
  my $username = random_number (10000, 99999);

  my $header =
  {
    "username" => $username
  };

  my $header_json = encode_json ($header);

  my $header_base64  = encode_base64url ($header_json, "");

  return $header_base64 . "." . "YjdgRQ";
}

1;
