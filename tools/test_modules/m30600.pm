#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Eksblowfish::Bcrypt qw (bcrypt bcrypt_hash en_base64);
use MIME::Base64               qw (decode_base64);
use Digest::SHA                qw (sha256_hex);

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

  my $sha256_word = sha256_hex ($word);

  my $attrs =
  {
    key_nul => 1,
    cost    => $cost,
    salt    => $salt,
  };

  my $hash = bcrypt_hash ($attrs, $sha256_word);

  return sprintf ('$2b$%s$%s%s', $cost, en_base64 ($salt), en_base64 ($hash));
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":", 33);

  return if $index1 < 1;

  my $hash = substr ($line, 0, $index1);
  my $word = substr ($line, $index1 + 1);

  my $index2 = index ($hash, "\$", 4);

  my $iter = substr ($hash, 4, $index2 - 4);

  my $plain_base64 = substr ($hash, $index2 + 1, 22);

  # base64 mapping

  my $base64   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  my $itoa64_2 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  my $encoded = "";

  for (my $i = 0; $i < length ($plain_base64); $i++)
  {
    my $char = substr ($plain_base64, $i, 1);

    $encoded .= substr ($base64, index ($itoa64_2, $char), 1);
  }

  my $salt = decode_base64 ($encoded);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

1;
