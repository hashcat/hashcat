#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::AuthEnc::GCM;
use Crypt::ScryptKDF qw (scrypt_raw);
use MIME::Base64     qw (decode_base64 encode_base64);

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word      = shift;
  my $salt      = shift;
  my $scrypt_n  = shift // 16384;
  my $scrypt_r  = shift // 8;
  my $scrypt_p  = shift // 1;
  my $iv        = shift // random_hex_string (24);
  my $data      = shift;
  my $tag       = shift;

  my $salt_bin = pack ("H*", $salt);

  my $key_bin = scrypt_raw ($word, $salt_bin, $scrypt_n, $scrypt_r, $scrypt_p, 32);

  my $iv_bin = pack ("H*", $iv);

  my $pt;

  if (defined $data)
  {
    my $data_bin = pack ("H*", $data);

    my $aes = Crypt::AuthEnc::GCM->new ("AES", $key_bin, $iv_bin);

    $pt = $aes->decrypt_add ($data_bin);

    my $tag_bin = pack ("H*", $tag);

    my $result_tag = $aes->decrypt_done ($tag_bin);

    if ($result_tag == 1)
    {
      ## correct password
    }
    else
    {
      $pt = random_bytes (32);
    }
  }
  else
  {
    $pt = random_bytes (32);
  }

  my $aes = Crypt::AuthEnc::GCM->new ("AES", $key_bin, $iv_bin);

  my $ct_bin = $aes->encrypt_add ($pt);

  my $tag_bin = $aes->encrypt_done ();

  my $hash = sprintf ('EXODUS:%u:%u:%u:%s:%s:%s:%s', $scrypt_n, $scrypt_r, $scrypt_p, encode_base64 ($salt_bin, ""), encode_base64 ($iv_bin, ""), encode_base64 ($ct_bin, ""), encode_base64 ($tag_bin, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = rindex ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 6) eq 'EXODUS';

  my ($signature, $scrypt_n, $scrypt_r, $scrypt_p, $salt, $iv, $data, $tag) = split ':', $hash;

  return unless defined $signature;
  return unless defined $scrypt_n;
  return unless defined $scrypt_r;
  return unless defined $scrypt_p;
  return unless defined $salt;
  return unless defined $iv;
  return unless defined $data;
  return unless defined $tag;

  $salt = decode_base64 ($salt);
  $iv   = decode_base64 ($iv);
  $data = decode_base64 ($data);
  $tag  = decode_base64 ($tag);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, unpack ("H*", $salt), $scrypt_n, $scrypt_r, $scrypt_p, unpack ("H*", $iv), unpack ("H*", $data), unpack ("H*", $tag));

  return ($new_hash, $word);
}

1;
