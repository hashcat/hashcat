#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (decode_base64 encode_base64);
use Digest::MD5  qw (md5_hex);
use Digest::SHA1 qw (sha1);
use Digest::HMAC qw (hmac);
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

my $ITERATIONS = 10000;
my $MD5_SALT   = ":mongo:";
my $HMAC_SALT  = "Server Key";

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // $ITERATIONS;
  my $user = shift // random_string (random_number (0, 57));

  my $pbkdf = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 20
  );

  my $md5_dgst = md5_hex ($user . $MD5_SALT . $word);

  my $pbkdf2_dgst = $pbkdf->PBKDF2 ($salt, $md5_dgst);

  my $hash_buf = hmac ($HMAC_SALT, $pbkdf2_dgst, \&sha1);

  my $hash = sprintf ('$mongodb-scram$*0*%s*%i*%s*%s', encode_base64 ($user, ""), $iter, encode_base64 ($salt, ""), encode_base64 ($hash_buf, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 17) eq '$mongodb-scram$*0';

  my (undef, undef, $user, $iter, $salt) = split ('\*', $hash);

  return unless defined ($user);
  return unless defined ($iter);
  return unless defined ($salt);

  return unless ($user =~ m/^[A-Za-z0-9+\/=]{0,76}$/);

  $user = decode_base64 ($user);

  return unless (length ($user) <= 57);

  return unless ($iter =~ m/^[1-9][0-9]{0,7}$/);

  $iter = int ($iter);

  return unless ($salt =~ m/^[A-Za-z0-9+\/=]{24}$/);

  $salt = decode_base64 ($salt);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter, $user);

  return ($new_hash, $word);
}

1;
