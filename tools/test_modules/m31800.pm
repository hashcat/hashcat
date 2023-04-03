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

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word              = shift;
  my $salt              = shift;
  my $iterations        = shift;
  my $email             = shift;
  my $algorithm         = shift;
  my $secret_key        = shift;
  my $ct                = shift;
  my $plaintext_length  = shift;
  my $iv                = shift;
  my $cryptext          = shift;
  my $expected_hmac     = shift;
  my $hmac_d_data       = shift;

  my $salt_bin = pack ("H*", $salt);

  my $hkdf_pass_salt = hkdf ($salt_bin, $email, 'SHA256', 32, "PBES2g-HS256");

  my $kdf = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iterations,
    output_len => 32
  );

  my $password_key = $kdf->PBKDF2 ($hkdf_pass_salt, $word);

  my $hkdf_key = hkdf ("798JRYLJVD423DC286TVMH43EB", "ASWWYB", 'SHA256', 32, "A3");

  my $muk = xor_len ($password_key, $hkdf_key, 32);

  my $pt;

  my $iv_bin;

  if (defined $ct)
  {
    my $ct_bin = pack ("H*", $ct);

    $iv_bin = substr ($ct_bin, 0 + length ("opdata01"), 16);

    my $data_bin = substr ($ct_bin, 0 + length ("opdata01") + 16, -16);
    my $tag_bin  = substr ($ct_bin, -16);

    my $aes = Crypt::AuthEnc::GCM->new ("AES", $muk, $iv_bin);

    $pt = $aes->decrypt_add ($data_bin);

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

  my $hash = sprintf
  (
    '$mobilekeychain$%s',

     unpack ("H*", "opdata01" . $iv_bin . $ct_bin . $tag_bin)
  );



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

  my (undef, $signature, $email, $salt_len, $salt, $algorithm, $secret_key, $iterations, $ct_len, $ct, $plaintext_length, $iv_len, $iv, $cryptext_len, $cryptext, $expected_hmac_len, $expected_hmac, $hmac_d_data_len, $hmac_d_data) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $email;
  return unless defined $salt_len;
  return unless defined $salt;
  return unless defined $algorithm;
  return unless defined $secret_key;
  return unless defined $iterations;
  return unless defined $ct_len;
  return unless defined $ct;
  return unless defined $plaintext_length;
  return unless defined $iv_len;
  return unless defined $iv;
  return unless defined $cryptext_len;
  return unless defined $cryptext;
  return unless defined $expected_hmac_len;
  return unless defined $expected_hmac;
  return unless defined $hmac_d_data_len;
  return unless defined $hmac_d_data;

  my $salt_bin          = pack ("H*", $salt);
  my $ct_bin            = pack ("H*", $ct);
  my $iv_bin            = pack ("H*", $iv);
  my $cryptext_bin      = pack ("H*", $cryptext);
  my $expected_hmac_bin = pack ("H*", $expected_hmac);
  my $hmac_d_data_bin   = pack ("H*", $hmac_d_data);

  return unless length ($salt_bin)          == $salt_len;
  return unless length ($ct_bin)            == $ct_len;
  return unless length ($iv_bin)            == $iv_len;
  return unless length ($cryptext_bin)      == $cryptext_len;
  return unless length ($expected_hmac_bin) == $expected_hmac_len;
  return unless length ($hmac_d_data_bin)   == $hmac_d_data_len;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $email, $algorithm, $secret_key, $ct, $plaintext_length, $iv, $cryptext, $expected_hmac, $hmac_d_data);

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
