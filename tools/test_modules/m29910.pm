#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Mode::ECB;
use Crypt::PBKDF2;

my $ENC_MAX_KEY_NUM             = 8;
my $ENC_NONCE_SIZE              = 8;
my $ENC_KEY_SIZE                = 16;
my $ENC_BLOCK_SIZE              = 16;
my $ENC_KEYCHAIN_SIZE           = 128;
my $ENC_DEFAULT_MD5_ITERATIONS  = 1000;

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $algo = shift // random_number (1, 4);
  my $iv   = shift // random_hex_string (16);
  my $ct   = shift;
  my $iter = shift // 100000;

  # pbkdf2 part

  my $nb_keys = 1 << ($algo - 1);

  my $key_len = $nb_keys * $ENC_KEY_SIZE;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => $key_len
  );

  my $salt_bin = pack ("H*", $salt);

  my $key = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $aes = Crypt::Mode::ECB->new ('AES', 0);

  my $aes_key = substr ($key, 0, $ENC_KEY_SIZE);

  ## decrypt encrypted data using PBKDF2 key

  my $iv_bin = pack ("H*", $iv);

  my @ivs;

  $ivs[0] = $iv_bin;

  for (my $i = 1; $i < $nb_keys; $i++)
  {
    my $next8 = substr ($key, $i * $ENC_KEY_SIZE, $ENC_NONCE_SIZE); ## its strange to skip 8 byte of key material every 16 byte

    $ivs[$i] = xor_len ($iv_bin, $next8, 8);
  }

  my $ctr_len = 16;

  my $ctr;

  for (my $i = 0, my $counter = 1; $i < ($ctr_len / $ENC_BLOCK_SIZE); $i++, $counter++)
  {
    my $counter_be = pack ("Q>", $counter);

    my $tmp_iv = $ivs[0] . $counter_be;

    my $enc = $aes->encrypt ($tmp_iv, $aes_key);

    my $out = $enc;

    for (my $i = 1; $i < $nb_keys; $i++)
    {
      my $tmp_iv = $ivs[$i] . $counter_be;

      my $enc = $aes->encrypt ($tmp_iv, $aes_key);

      $out = xor_len ($enc, $out, $ENC_BLOCK_SIZE);
    }

    $ctr .= $out;
  }

  my $pt_bin;

  if (defined $ct)
  {
    my $ct_bin = pack ("H*", $ct);

    $pt_bin = xor_len (substr ($ctr, 4, 8), $ct_bin, 8);

    # we compare only 56 bit, see https://github.com/hashcat/hashcat/issues/3467

    if (substr ($pt_bin, 0, 7) eq "\xd2\xc3\xb4\xa1\x00\x00\x00")
    {
      # ok
    }
    else
    {
      $pt_bin = "\xff\xff\xff\xff\xff\xff\xff\xff";
    }
  }
  else
  {
    $pt_bin = "\xd2\xc3\xb4\xa1\x00\x00\x00\x30";
  }

  my $ct_bin = xor_len (substr ($ctr, 4, 8), $pt_bin, 8);

  my $hash = sprintf ('$encdv-pbkdf2$1$%d$%s$%s$32$%s$%d', $algo, unpack ("H*", $iv_bin), unpack ("H*", $ct_bin), unpack ("H*", $salt_bin), $iter);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 14) eq '$encdv-pbkdf2$';

  my (undef, $signature, $version, $algo, $iv, $ct, $salt_len, $salt, $iter) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $algo;
  return unless defined $iv;
  return unless defined $ct;
  return unless defined $salt_len;
  return unless defined $salt;
  return unless defined $iter;

  return unless ($version == 1);
  return unless ($algo >= 1);
  return unless ($algo <= 4);
  return unless ($salt_len == 32);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $algo, $iv, $ct, $iter);

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
