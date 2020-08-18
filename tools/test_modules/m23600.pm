#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::Mode::ECB;

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

my $AXCRYPT_MAGIC = pack ("H*", "a6a6a6a6a6a6a6a6");

sub module_generate_hash
{
  my $word      = shift;
  my $salt_wrap = shift;
  my $iter_wrap = shift // 10000;
  my $data      = shift;
  my $salt_kdf  = shift // random_bytes (32);
  my $iter_kdf  = shift //  1000;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iter_kdf,
    output_len => 64
  );

  # most heavy part (PBKDF2-HMAC-SHA512):

  my $KEK = $pbkdf2->PBKDF2 ($salt_kdf, $word);

  # reduce 64 bytes of key to 16 bytes (why not just use 16 byte output length o.O ?)

  $KEK = substr ($KEK,  0, 32) ^ substr ($KEK, 32, 32);

  $KEK = $KEK ^ substr ($salt_wrap, 0, 32);

  my $aes = Crypt::Mode::ECB->new ('AES', 0);

  if (defined ($data)) # decrypt
  {
    # unwrap:

    my $data_mod = $data;

    for (my $j = $iter_wrap - 1; $j >= 0; $j--)
    {
      for (my $k = 6; $k >= 1; $k--)
      {
        my $idx = 6 * $j + $k;

        my $block =  substr ($data_mod,      0, 4) .
                    (substr ($data_mod,      4, 4) ^ pack ("L>", $idx)) .
                     substr ($data_mod, $k * 8, 8);

        $block = $aes->decrypt ($block, $KEK);

        substr ($data_mod,      0, 8) = substr ($block, 0, 8);
        substr ($data_mod, $k * 8, 8) = substr ($block, 8, 8);
      }
    }

    if (index ($data_mod, $AXCRYPT_MAGIC) != 0)
    {
      $data = "WRONG";
    }
  }
  else # encrypt
  {
    # wrap:

    $data = $AXCRYPT_MAGIC . random_bytes (136);

    for (my $j = 0; $j < $iter_wrap; $j++)
    {
      for (my $k = 1; $k <= 6; $k++)
      {
        my $idx = 6 * $j + $k;

        my $block = substr ($data,      0, 8) .
                    substr ($data, $k * 8, 8);

        $block = $aes->encrypt ($block, $KEK);

        substr ($block, 4, 4) ^= pack ("L>", $idx);

        substr ($data,      0, 8) = substr ($block, 0, 8);
        substr ($data, $k * 8, 8) = substr ($block, 8, 8);
      }
    }
  }

  my $hash = sprintf ("\$axcrypt\$*2*%i*%s*%s*%i*%s", $iter_wrap, unpack ("H*", $salt_wrap), unpack ("H*", $data), $iter_kdf, unpack ("H*", $salt_kdf));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 11) eq '$axcrypt$*2';

  my (undef, undef, $iter_wrap, $salt_wrap, $data, $iter_kdf, $salt_kdf) = split ('\*', $hash);

  return unless defined ($iter_wrap);
  return unless defined ($salt_wrap);
  return unless defined ($data);
  return unless defined ($iter_kdf);
  return unless defined ($salt_kdf);

  return unless ($iter_wrap =~ m/^[0-9]{1,7}$/);
  return unless ($salt_wrap =~ m/^[0-9a-fA-F]+$/);
  return unless ($data      =~ m/^[0-9a-fA-F]+$/);
  return unless ($iter_kdf  =~ m/^[0-9]{1,7}$/);
  return unless ($salt_kdf  =~ m/^[0-9a-fA-F]+$/);

  $salt_wrap = pack ("H*", $salt_wrap);
  $data      = pack ("H*", $data);
  $salt_kdf  = pack ("H*", $salt_kdf);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt_wrap, $iter_wrap, $data, $salt_kdf, $iter_kdf);

  return ($new_hash, $word);
}

1;
