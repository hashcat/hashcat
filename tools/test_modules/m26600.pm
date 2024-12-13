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
      # generate plaintext

      # TODO now the data is all 0xff, would be better to have it mimic the same structure as the reference data:
      # [{"type":"HD Key Tree","data":{"mnemonic":[112,97,121,109,101,110,116,32,117,112,115,101,116,32,109,101,116,97,108,32,99,104,97,112,116,101,114,32,114,117,110,32,97,100,109,105,116,32,109,101,97,115,117,114,101,32,114,101,109,105,110,100,32,115,117,112,112,108,121,32,104,111,112,101,32,101,110,101,109,121,32,104,101,100,103,101,104,111,103],"numberOfAccounts":1,"hdPath":"m/44'/60'/0'/0"}}]
      # generated from tools/2hashcat_tests/metamask2hashcat-test.py
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
