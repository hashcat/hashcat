#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::DES;

sub module_constraints { [[4, 4], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub des_ecb_encrypt
{
  my ($key, $data) = @_;

  my $cipher = Crypt::DES->new ($key);

  return $cipher->encrypt ($data);
}

sub des_ecb_decrypt
{
  my ($key, $data) = @_;

  my $cipher = Crypt::DES->new ($key);

  return $cipher->decrypt ($data);
}

sub tdes_ecb_encrypt
{
  my ($key16, $data) = @_;

  my $k1 = substr ($key16, 0, 8);
  my $k2 = substr ($key16, 8, 8);

  return des_ecb_encrypt ($k1, des_ecb_decrypt ($k2, des_ecb_encrypt ($k1, $data)));
}

sub tdes_ecb_decrypt
{
  my ($key16, $data) = @_;

  my $k1 = substr ($key16, 0, 8);
  my $k2 = substr ($key16, 8, 8);

  return des_ecb_decrypt ($k1, des_ecb_encrypt ($k2, des_ecb_decrypt ($k1, $data)));
}

sub exclusive_or
{
  my ($in1, $in2) = @_;

  my $out = "";

  for (my $i = 0; $i < length ($in1); $i++)
  {
    $out .= chr (ord (substr ($in1, $i, 1)) ^ ord (substr ($in2, $i, 1)));
  }

  return $out;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $mode    = shift // 1;
  my $segment = shift // (random_number (1, 4));
  my $lfsr    = shift // 0;
  my $erndb   = shift;
  my $blk1    = shift;
  my $blk2    = shift;
  my $basekey = shift;

  # word is 4 bytes = the candidate key segment

  my $base_key_bin;

  if (defined $basekey)
  {
    $base_key_bin = pack ("H*", $basekey);
  }
  else
  {
    $base_key_bin = random_bytes (16);

    # zero out the segment we are bruting
    my $seg_offset = ($segment - 1) * 4;

    substr ($base_key_bin, $seg_offset, 4) = "\x00\x00\x00\x00";
  }

  # insert the candidate (word) into the key
  my $full_key = $base_key_bin;

  my $seg_offset = ($segment - 1) * 4;

  substr ($full_key, $seg_offset, 4) = $word;

  if ($mode == 1)
  {
    # reader mode we generate a valid auth exchange

    my $rndb_bin;

    if (defined $erndb)
    {
      # verify mode: reconstruct from provided values
      $rndb_bin = tdes_ecb_decrypt ($full_key, pack ("H*", $erndb));
    }
    else
    {
      $rndb_bin = random_bytes (8);
    }

    my $erndb_bin = tdes_ecb_encrypt ($full_key, $rndb_bin);

    # RndB' = rotate left 1 byte
    my $rndb_prime = substr ($rndb_bin, 1) . substr ($rndb_bin, 0, 1);

    # RndA is random
    my $rnda_bin;

    if (defined $blk1)
    {
      # reconstruct RndA from CBC_Block1
      my $blk1_bin = pack ("H*", $blk1);
      my $dec_blk1 = tdes_ecb_decrypt ($full_key, $blk1_bin);

      $rnda_bin = exclusive_or ($dec_blk1, $erndb_bin);
    }
    else
    {
      $rnda_bin = random_bytes (8);
    }

    # CBC encrypt: Block1 = E(RndA ^ ERndB), Block2 = E(RndB' ^ Block1)
    my $cbc_blk1 = tdes_ecb_encrypt ($full_key, exclusive_or ($rnda_bin, $erndb_bin));
    my $cbc_blk2 = tdes_ecb_encrypt ($full_key, exclusive_or ($rndb_prime, $cbc_blk1));

    my $hash = sprintf ('$mfulc$%d$%d$%d$%s$%s$%s$%s',
      $mode,
      $segment,
      $lfsr,
      unpack ("H*", $erndb_bin),
      unpack ("H*", $cbc_blk1),
      unpack ("H*", $cbc_blk2),
      unpack ("H*", $base_key_bin));

    return $hash;
  }
  else
  {
    # counterfeit mode we do not generate new hashes for test, we just re-encode from provided values

    my $hash = sprintf ('$mfulc$%d$%d$%d$%s$%s$%s$%s',
      $mode,
      $segment,
      $lfsr,
      $erndb  // ("00" x 8),
      $blk1   // ("00" x 8),
      $blk2   // ("00" x 8),
      unpack ("H*", $base_key_bin));

    return $hash;
  }
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 7) eq '$mfulc$';

  my (undef, $mode, $segment, $lfsr, $erndb, $blk1, $blk2, $basekey) = split ('\$', $hash);

  return unless defined $mode;
  return unless defined $segment;
  return unless defined $lfsr;
  return unless defined $erndb;
  return unless defined $blk1;
  return unless defined $blk2;
  return unless defined $basekey;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $mode, $segment, $lfsr, $erndb, $blk1, $blk2, $basekey);

  return ($new_hash, $word);
}

1;
