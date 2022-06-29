#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (decode_base64 encode_base64);
use Digest::SHA  qw (sha256);
use Digest::HMAC qw (hmac);
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [28, 28], [-1, -1], [-1, -1], [-1, -1]] }

my $ITERATIONS  = 4096;
my $HMAC_SALT   = "Server Key";
my $HMAC_SALT_2 = "Client Key";

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // $ITERATIONS;

  my $pbkdf = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => 32
  );

  my $pbkdf2_dgst = $pbkdf->PBKDF2 ($salt, $word);

  my $server_key =         hmac ($HMAC_SALT,   $pbkdf2_dgst, \&sha256);
  my $stored_key = sha256 (hmac ($HMAC_SALT_2, $pbkdf2_dgst, \&sha256));

  my $hash = sprintf ('SCRAM-SHA-256$%i:%s$%s:%s', $iter, encode_base64 ($salt, ""), encode_base64 ($stored_key, ""), encode_base64 ($server_key, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = rindex ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 13) eq 'SCRAM-SHA-256';

  my (undef, $iter, $salt) = split (':|\$', $hash);

  return unless defined ($iter);
  return unless defined ($salt);

  return unless ($iter =~ m/^[1-9][0-9]{0,7}$/);

  $iter = int ($iter);

  return unless ($salt =~ m/^[A-Za-z0-9+\/=]{0,88}$/);

  $salt = decode_base64 ($salt);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

1;
