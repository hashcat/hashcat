#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64;

sub module_constraints { [[0, 256], [16, 32], [-1, -1], [-1, -1], [-1, -1]] }

# QNX 7 /etc/shadow (SHA512): PBKDF2-HMAC-SHA512, 4096 rounds by default,
# 64-byte derived key. Serialized as @S@<base64(dk)>@<base64(salt)>. The parser
# reuses macOS kern_type 7100; the leading "S" tag can carry a custom round
# count as "S,<rounds>". Salt bytes are used verbatim (base64 on the wire).

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 4096;

  if (length $salt == 0)
  {
    $salt = random_numeric_string (16);
  }

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iter
  );

  my $dk       = $pbkdf2->PBKDF2 ($salt, $word);
  my $hash_b64 = encode_base64 ($dk,   '');
  my $salt_b64 = encode_base64 ($salt, '');

  my $tag = ($iter == 4096) ? 'S' : "S,$iter";

  my $hash = sprintf ('@%s@%s@%s', $tag, $hash_b64, $salt_b64);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $hash_in = substr ($line, 0, $index1);
  my $word    = substr ($line, $index1 + 1);

  my @parts = split ('@', $hash_in);

  return unless scalar @parts >= 4;      # ('', tag, hash, salt)

  my $tag  = $parts[1];
  my $salt = decode_base64 ($parts[3]);

  my $iter = 4096;

  if ($tag =~ /^S,(\d+)$/)
  {
    $iter = $1;
  }

  return if (int ($iter) < 1);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
