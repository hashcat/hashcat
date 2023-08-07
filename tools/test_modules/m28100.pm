#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1 sha512);
use Crypt::PBKDF2;
use Encode;

sub module_constraints { [[4, 127], [8, 8], [-1, -1], [-1, -1], [-1, -1]] }

#
# Helper functions:
#

sub exclusive_or
{
  my $in1 = shift;
  my $in2 = shift;

  # MIN () function (should always be 16 for us):
  # my $len = (length ($in1) <= length ($in2)) ? length ($in2) : length ($in1);

  # padding if input not multiple of block size:
  # $in1 .= "\x00" x ($AES256_IGE_BLOCK_SIZE - $len);
  # $in2 .= "\x00" x ($AES256_IGE_BLOCK_SIZE - $len);

  my $out = "";

  for (my $i = 0; $i < length $in1; $i++) # $i < $len
  {
    $out .= chr (ord (substr ($in1, $i, 1)) ^ ord (substr ($in2, $i, 1)));
  }

  return $out;
}

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $iter   = shift // 10000;
  my $mk     = shift // random_hex_string (128);
  my $hmac   = shift // random_hex_string (64);
  my $blob   = shift // random_hex_string (1384);
  my $magicv = shift // "785435725a573571565662727670754100";

  my $salt_bin   = pack ("H*", $salt);
  my $mk_bin     = pack ("H*", $mk);
  my $hmac_bin   = pack ("H*", $hmac);
  my $blob_bin   = pack ("H*", $blob);
  my $magicv_bin = pack ("H*", $magicv);

  ## convert_userpin_to_secretpin()
  ## this looks strange. what if the user password is outside 0x20 - 0x7f?
  ## from some testing, it seems MS prevents the user to use any non-ascii characters

  my $stage1_hexpin = uc (encode ("UTF-16LE", unpack ("H*", $word)));

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => 32
  );

  my $stage2_pbkdf2 = $pbkdf2->PBKDF2 ($salt_bin, $stage1_hexpin);

  my $stage3_hexconvert = uc (encode ("UTF-16LE", unpack ("H*", $stage2_pbkdf2)));

  my $stage4_sha512 = sha512 ($stage3_hexconvert);

  ## is_signature_matching()

  my $masterkey = sha1 ($mk_bin) . "\x00" x 108;

  my $sub_digest_seed  = exclusive_or ($masterkey, "\x36" x 128);
  my $main_digest_seed = exclusive_or ($masterkey, "\x5c" x 128);

  my $sub_digest = sha512 ($sub_digest_seed . $hmac_bin . $magicv_bin . $stage4_sha512 . $blob_bin);

  my $main_digest = sha512 ($main_digest_seed . $sub_digest);

  my $hash = sprintf ("\$WINHELLO\$*SHA512*%i*%s*%s*%s*%s*%s*%s", $iter, unpack ("H*", $salt_bin), unpack ("H*", $main_digest), unpack ("H*", $mk_bin), unpack ("H*", $hmac_bin), unpack ("H*", $blob_bin), unpack ("H*", $magicv_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  my ($signature, $algo, $iter, $pin_salt, $sign, $mk, $hmac, $verify_blob, $magicv) = split '\*', $hash;

  return unless defined $signature;
  return unless defined $algo;
  return unless defined $iter;
  return unless defined $pin_salt;
  return unless defined $sign;
  return unless defined $mk;
  return unless defined $hmac;
  return unless defined $verify_blob;
  return unless defined $magicv;

  return unless ($signature eq '$WINHELLO$');
  return unless ($algo eq 'SHA512');
  return unless (length $pin_salt eq 8);
  return unless (length $sign eq 128);
  return unless (length $mk eq 128);
  return unless (length $hmac eq 64);
  return unless (length $verify_blob eq 1384);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $pin_salt, $iter, $mk, $hmac, $verify_blob, $magicv);

  return ($new_hash, $word);
}

1;
