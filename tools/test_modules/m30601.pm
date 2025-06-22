#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Eksblowfish::Bcrypt qw (bcrypt_hash de_base64 en_base64);
use MIME::Base64               qw (encode_base64);
use Digest::SHA                qw (hmac_sha256);

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  my $cost = "10";

  if (length ($iter))
  {
    $cost = $iter;
  }

  my $encoded_salt = en_base64 ( $salt );
  my $sha256_word = hmac_sha256 ( $word, $encoded_salt );
  my $padded_b64a_sha256_word = encode_base64 ( $sha256_word ); # NOT a bug - the implementation of passlib uses regular base64 here
  chomp $padded_b64a_sha256_word;

  my $attrs =
  {
    key_nul => 1,
    cost    => $cost,
    salt    => $salt,
  };

  my $hash = bcrypt_hash ($attrs, $padded_b64a_sha256_word);

  return sprintf ('$bcrypt-sha256$v=2,t=2b,r=%s$%s$%s', $cost, $encoded_salt, en_base64 ($hash));
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":", 82);

  return if $index1 < 1;

  my $hash = substr ($line, 0, $index1);
  my $word = substr ($line, $index1 + 1);

  my $index2 = index ($hash, "=", 24);
  my $index3 = index ($hash, "\$", 24);

  my $iter = substr ($hash, $index2, $index3 - $index2);

  my $plain_base64 = substr ($hash, $index3 + 1, 22);

  # use base64 from bcrypt module
  my $salt = de_base64($plain_base64);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter, $hash);

  return ($new_hash, $word);
}

1;
