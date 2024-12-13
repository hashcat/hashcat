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
use Crypt::KeyDerivation ':all';

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word        = shift;
  my $hkdf_salt   = shift;
  my $hkdf_key    = shift // random_hex_string (64);
  my $iterations  = shift // 100000;
  my $iv          = shift // (random_number (0,1) ? random_hex_string (32) : random_hex_string (24));
  my $ct          = shift;
  my $tag         = shift;
  my $email       = shift // "31800\@hashcat.net";

  my $hkdf_salt_bin = pack ("H*", $hkdf_salt);

  my $kdf = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iterations,
    output_len => 32
  );

  my $password_key = $kdf->PBKDF2 ($hkdf_salt_bin, $word);

  my $hkdf_key_bin = pack ("H*", $hkdf_key);

  my $muk = xor_len ($password_key, $hkdf_key_bin, 32);

  my $pt;

  my $iv_bin = pack ("H*", $iv);

  if (defined $ct)
  {
    my $ct_bin = pack ("H*", $ct);

    my $tag_bin = pack ("H*", $tag);

    my $aes = Crypt::AuthEnc::GCM->new ("AES", $muk, $iv_bin);

    $pt = $aes->decrypt_add ($ct_bin);

    my $result_tag = $aes->decrypt_done ($tag_bin);

    if ($result_tag == 1)
    {
      ## correct password
    }
    else
    {
      $pt = "{'key_ops': ['decrypt', 'encrypt'], 'kty': 'oct', 'alg': 'A256GCM', 'k': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=', 'ext': True, 'kid': 'xxxxxxxxxxxxxxxxxxxxxxxxxx'}";
    }
  }
  else
  {
    $pt = "{'key_ops': ['decrypt', 'encrypt'], 'kty': 'oct', 'alg': 'A256GCM', 'k': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=', 'ext': True, 'kid': 'xxxxxxxxxxxxxxxxxxxxxxxxxx'}";
  }

  my $aes = Crypt::AuthEnc::GCM->new ("AES", $muk, $iv_bin);

  my $ct_bin = $aes->encrypt_add ($pt);

  my $tag_bin = $aes->encrypt_done ();

  ## so far so good

  my $hash = sprintf ('$mobilekeychain$%s$%s$%s$%u$%s$%s$%s', $email, unpack ("H*", $hkdf_salt_bin), unpack ("H*", $hkdf_key_bin), $iterations, unpack ("H*", $iv_bin), unpack ("H*", $ct_bin), unpack ("H*", $tag_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 16) eq '$mobilekeychain$';

  my (undef, $signature, $email, $hkdf_salt, $hkdf_key, $iterations, $iv, $ct, $tag) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $email;
  return unless defined $hkdf_salt;
  return unless defined $hkdf_key;
  return unless defined $iterations;
  return unless defined $iv;
  return unless defined $ct;
  return unless defined $tag;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $hkdf_salt, $hkdf_key, $iterations, $iv, $ct, $tag, $email);

  return ($new_hash, $word);
}

sub xor_len
{
  my $in1 = shift;
  my $in2 = shift;
  my $len = shift;

  my $out;

  for (my $i = 0; $i < $len; $i++)
  {
    $out .= chr (ord (substr ($in1, $i, 1)) ^ ord (substr ($in2, $i, 1)));
  }

  return $out;
}

1;
