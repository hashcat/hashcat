#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::DES;

sub module_constraints { [[8, 8], [8, 8], [-1, -1], [-1, -1], [-1, -1]] }

sub reflect8
{
  my $b = shift;

  $b = (($b & 0xF0) >> 4) | (($b & 0x0F) << 4);
  $b = (($b & 0xCC) >> 2) | (($b & 0x33) << 2);
  $b = (($b & 0xAA) >> 1) | (($b & 0x55) << 1);

  return $b & 0xFF;
}

sub hash0
{
  my ($des_out0, $des_out1) = @_;

  my $x = ($des_out0 >> 24) & 0xFF;
  my $y = ($des_out0 >> 16) & 0xFF;

  my $hi = $des_out0 & 0xFFFF;
  my $lo = $des_out1;

  my @zs;

  $zs[0] =  $lo        & 0x3F;
  $zs[1] = ($lo >>  6) & 0x3F;
  $zs[2] = ($lo >> 12) & 0x3F;
  $zs[3] = ($lo >> 18) & 0x3F;
  $zs[4] = ($lo >> 24) & 0x3F;
  $zs[5] = (($hi & 0x0F) << 2) | ($lo >> 30);
  $zs[6] = ($hi >>  4) & 0x3F;
  $zs[7] = ($hi >> 10) & 0x3F;

  my @zP;

  $zP[0] = ($zs[0] % 63) + 0;
  $zP[1] = ($zs[1] % 62) + 1;
  $zP[2] = ($zs[2] % 61) + 2;
  $zP[3] = ($zs[3] % 60) + 3;
  $zP[4] = ($zs[4] % 64) + 0;
  $zP[5] = ($zs[5] % 63) + 1;
  $zP[6] = ($zs[6] % 62) + 2;
  $zP[7] = ($zs[7] % 61) + 3;

  for (my $i = 3; $i >= 1; $i--)
  {
    for (my $j = $i - 1; $j >= 0; $j--)
    {
      if ($zP[$i] == $zP[$j])
      {
        $zP[$i] = $j;
      }
    }
  }

  for (my $i = 7; $i >= 5; $i--)
  {
    for (my $j = $i - 1; $j >= 4; $j--)
    {
      if ($zP[$i] == $zP[$j])
      {
        $zP[$i] = $j - 4;
      }
    }
  }

  my @pi = (
    0x0F, 0x17, 0x1B, 0x1D, 0x1E, 0x27, 0x2B, 0x2D,
    0x2E, 0x33, 0x35, 0x39, 0x36, 0x3A, 0x3C, 0x47,
    0x4B, 0x4D, 0x4E, 0x53, 0x55, 0x56, 0x59, 0x5A,
    0x5C, 0x63, 0x65, 0x66, 0x69, 0x6A, 0x6C, 0x71,
    0x72, 0x74, 0x78
  );

  my $p = $pi[$x % 35];

  if ($x & 1)
  {
    $p = (~$p) & 0xFF;
  }

  my $li = 0;
  my $ri = 4;
  my @zt;

  for (my $bit = 0; $bit <= 7; $bit++)
  {
    if (($p >> $bit) & 1)
    {
      $zt[$bit] = $zP[$li] + 1;
      $li++;
    }
    else
    {
      $zt[$bit] = $zP[$ri];
      $ri++;
    }
  }

  my @div_key;

  for (my $i = 0; $i < 8; $i++)
  {
    my $y_bit = ($y >> $i) & 1;
    my $zt_i  = ($zt[$i] << 1) & 0xFE;
    my $p_i   = ($p >> $i) & 1;

    my $ki = $y_bit << 7;

    if ($ki)
    {
      $ki |= (~$zt_i) & 0x7E;
      $ki |= $p_i & 1;
      $ki = ($ki + 1) & 0xFF;
    }
    else
    {
      $ki |= $zt_i & 0x7E;
      $ki |= (~$p_i) & 1;
    }

    $div_key[$i] = $ki & 0xFF;
  }

  return @div_key;
}

sub iclass_successor
{
  my ($k, $t, $l, $r, $b, $y_bit) = @_;

  my $r0 = ($r >> 7) & 1;
  my $r4 = ($r >> 3) & 1;
  my $r7 =  $r       & 1;

  my $Tt = (($t >> 15) & 1) ^ (($t >> 14) & 1)
         ^ (($t >> 10) & 1) ^ (($t >>  8) & 1)
         ^ (($t >>  5) & 1) ^ (($t >>  4) & 1)
         ^ (($t >>  1) & 1) ^ ( $t        & 1);

  my $Bt = (($b >> 6) & 1) ^ (($b >> 5) & 1)
         ^ (($b >> 4) & 1) ^ ( $b       & 1);

  my $nt = (($t >> 1) | ((($Tt ^ $r0 ^ $r4) & 1) << 15)) & 0xFFFF;
  my $nb = (($b >> 1) | ((($Bt ^ $r7)       & 1) << 7))   & 0xFF;

  my $r1 = ($r >> 6) & 1;
  my $r2 = ($r >> 5) & 1;
  my $r3 = ($r >> 4) & 1;
  my $r5 = ($r >> 2) & 1;
  my $r6 = ($r >> 1) & 1;

  my $z0 = ($r0 & $r2) ^ ($r1 & ($r3 ^ 1)) ^ ($r2 | $r4);
  my $z1 = ($r0 | $r2) ^ ($r5 | $r7) ^ $r1 ^ $r6 ^ $Tt ^ $y_bit;
  my $z2 = ($r3 & ($r5 ^ 1)) ^ ($r4 & $r6) ^ $r7 ^ $Tt;

  my $sel = (($z0 & 1) << 2) | (($z1 & 1) << 1) | ($z2 & 1);
  my $val = ($k->[$sel] ^ $nb) & 0xFF;

  my $nl = ($val + $l + $r) & 0xFF;
  my $nr = ($val + $l)      & 0xFF;

  return ($nt, $nl, $nr, $nb);
}

sub iclass_mac
{
  my ($rev_ccnr, $div_key) = @_;

  my $t = 0xE012;
  my $l = (($div_key->[0] ^ 0x4C) + 0xEC) & 0xFF;
  my $r = (($div_key->[0] ^ 0x4C) + 0x21) & 0xFF;
  my $b = 0x4C;

  for (my $i = 0; $i < 12; $i++)
  {
    my $rb = $rev_ccnr->[$i];

    for (my $bit = 7; $bit >= 0; $bit--)
    {
      ($t, $l, $r, $b) = iclass_successor ($div_key, $t, $l, $r, $b, ($rb >> $bit) & 1);
    }
  }

  my @mac = (0, 0, 0, 0);

  for (my $i = 0; $i < 4; $i++)
  {
    for (my $bit = 7; $bit >= 0; $bit--)
    {
      $mac[$i] |= (($r >> 2) & 1) << $bit;

      ($t, $l, $r, $b) = iclass_successor ($div_key, $t, $l, $r, $b, 0);
    }
  }

  return (reflect8 ($mac[0]) << 24)
       | (reflect8 ($mac[1]) << 16)
       | (reflect8 ($mac[2]) <<  8)
       | (reflect8 ($mac[3])      );
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my ($csn_hex, $ccnr1_hex, $ccnr2_hex);

  if (defined $salt)
  {
    my @parts = split (/\$/, $salt);

    $csn_hex   = $parts[0];
    $ccnr1_hex = $parts[1];
    $ccnr2_hex = $parts[2] // $parts[1];
  }
  else
  {
    $csn_hex   = unpack ("H16", pack ("C8", map { int (rand (256)) } 1..8));
    $ccnr1_hex = unpack ("H24", pack ("C12", map { int (rand (256)) } 1..12));
    $ccnr2_hex = $ccnr1_hex;
  }

  my $csn_bin = pack ("H16", $csn_hex);

  my $cipher = new Crypt::DES ($word);
  my $crypted_csn = $cipher->encrypt ($csn_bin);

  my @ct_bytes = unpack ("C8", $crypted_csn);

  my $des_out0 = ($ct_bytes[0] << 24) | ($ct_bytes[1] << 16) | ($ct_bytes[2] << 8) | $ct_bytes[3];
  my $des_out1 = ($ct_bytes[4] << 24) | ($ct_bytes[5] << 16) | ($ct_bytes[6] << 8) | $ct_bytes[7];

  my @div_key = hash0 ($des_out0, $des_out1);

  my @ccnr1_bytes = unpack ("C12", pack ("H24", $ccnr1_hex));
  my @rev_ccnr1;
  for (my $i = 0; $i < 12; $i++) { $rev_ccnr1[$i] = reflect8 ($ccnr1_bytes[$i]); }

  my $mac1 = iclass_mac (\@rev_ccnr1, \@div_key);

  my @ccnr2_bytes = unpack ("C12", pack ("H24", $ccnr2_hex));
  my @rev_ccnr2;
  for (my $i = 0; $i < 12; $i++) { $rev_ccnr2[$i] = reflect8 ($ccnr2_bytes[$i]); }

  my $mac2 = iclass_mac (\@rev_ccnr2, \@div_key);

  my $mac1_hex = sprintf ("%08x", $mac1);
  my $mac2_hex = sprintf ("%08x", $mac2);

  my $hash = sprintf ("\$iclass\$%s\$%s\$%s\$%s\$%s", $csn_hex, $ccnr1_hex, $mac1_hex, $ccnr2_hex, $mac2_hex);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 8) eq '$iclass$';

  my $rest = substr ($hash, 8);
  my @parts = split (/\$/, $rest);

  return unless scalar @parts >= 3;

  my $csn_hex   = $parts[0];
  my $ccnr1_hex = $parts[1];
  my $ccnr2_hex = (scalar @parts >= 5) ? $parts[3] : $parts[1];

  my $salt = "${csn_hex}\$${ccnr1_hex}\$${ccnr2_hex}";

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
