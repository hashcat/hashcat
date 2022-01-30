#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::AuthEnc::GCM;
use MIME::Base64 qw (decode_base64 encode_base64);

sub module_constraints { [[8, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iv   = shift // random_hex_string (32);
  my $ct   = shift;

  my $ct_min_len = 30;
  my $ct_max_len = 3136;

  my $kdf = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => 10000,
    output_len => 32
  );

  my $salt_bin = pack ("H*", $salt);

  my $key = $kdf->PBKDF2 ($salt_bin, $word);

  my $iv_bin = pack ("H*", $iv);

  my $pt;

  if (defined $ct)
  {
    my $ct_bin = pack ("H*", $ct);

    my $data_bin = substr ($ct_bin, 0, -16);
    my $tag_bin  = substr ($ct_bin, -16);

    my $aes = Crypt::AuthEnc::GCM->new ("AES", $key, $iv_bin);

    $pt = $aes->decrypt_add  ($data_bin);

    my $result_tag = $aes->decrypt_done ($tag_bin);

    if ($result_tag == 1)
    {
      ## correct password
    }
    else
    {
      $pt = "\xff" x ($ct_min_len + int (rand ($ct_max_len - $ct_min_len)) + 1);
    }
  }
  else
  {
    $pt = "\xff" x ($ct_min_len + int (rand ($ct_max_len - $ct_min_len)) + 1);
  }

  my $aes = Crypt::AuthEnc::GCM->new ("AES", $key, $iv_bin);

  my $ct_bin = $aes->encrypt_add ($pt);

  my $tag_bin = $aes->encrypt_done ();

  my $hash = sprintf ('$metamask$%s$%s$%s', encode_base64 ($salt_bin, ""), encode_base64 ($iv_bin, ""), encode_base64 ($ct_bin . $tag_bin, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 10) eq '$metamask$';

  my (undef, $signature, $salt, $iv, $ct) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $salt;
  return unless defined $iv;
  return unless defined $ct;

  my $salt_bin = decode_base64 ($salt);
  my $iv_bin   = decode_base64 ($iv);
  my $ct_bin   = decode_base64 ($ct);

  return unless length $salt_bin == 32;
  return unless length $iv_bin   == 16;

  my $ct_len = length ($ct_bin);
  my $ct_min_len = 30;
  my $ct_max_len = 3136;

  return unless ($ct_len >= $ct_min_len && $ct_len <= $ct_max_len);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, unpack ("H*", $salt_bin), unpack ("H*", $iv_bin), unpack ("H*", $ct_bin));

  return ($new_hash, $word);
}

1;
