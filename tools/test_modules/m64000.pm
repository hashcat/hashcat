#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[5, 5], [8, 8], [-1, -1], [-1, -1], [-1, -1]] }

sub reflect8
{
  my $b = shift;

  $b = (($b & 0xF0) >> 4) | (($b & 0x0F) << 4);
  $b = (($b & 0xCC) >> 2) | (($b & 0x33) << 2);
  $b = (($b & 0xAA) >> 1) | (($b & 0x55) << 1);

  return $b & 0xFF;
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

sub gen_key
{
  my ($pk, $index) = @_;

  my @key;

  for (my $i = 0; $i < 8; $i++)
  {
    $key[$i] = $pk->[$i];
  }

  my $carry = $index;

  for (my $j = 7; $j >= 0; $j--)
  {
    $key[$j] = ($pk->[$j] & 0x07) | (($carry & 0x1F) << 3);
    $key[$j] &= 0xFF;

    $carry >>= 5;

    last if $carry == 0;
  }

  return @key;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my ($pk_hex, $ccnr1_hex, $ccnr2_hex);

  if (defined $salt)
  {
    my @parts = split (/\$/, $salt);

    $pk_hex    = $parts[0];
    $ccnr1_hex = $parts[1];
    $ccnr2_hex = $parts[2] // $parts[1];
  }
  else
  {
    $pk_hex    = unpack ("H16", pack ("C8", map { int (rand (256)) } 1..8));
    $ccnr1_hex = unpack ("H24", pack ("C12", map { int (rand (256)) } 1..12));
    $ccnr2_hex = $ccnr1_hex;
  }

  my @pk = unpack ("C8", pack ("H16", $pk_hex));

  my @pw_bytes = unpack ("C*", $word);

  my $index = 0;

  for (my $i = 0; $i < scalar @pw_bytes; $i++)
  {
    $index |= $pw_bytes[$i] << ($i * 8);
  }

  my @div_key = gen_key (\@pk, $index);

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

  my $hash = sprintf ("\$iclass_leg\$%s\$%s\$%s\$%s\$%s", $pk_hex, $ccnr1_hex, $mac1_hex, $ccnr2_hex, $mac2_hex);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 12) eq '$iclass_leg$';

  my $rest = substr ($hash, 12);
  my @parts = split (/\$/, $rest);

  return unless scalar @parts >= 3;

  my $pk_hex    = $parts[0];
  my $ccnr1_hex = $parts[1];
  my $ccnr2_hex = (scalar @parts >= 5) ? $parts[3] : $parts[1];

  my $salt = "${pk_hex}\$${ccnr1_hex}\$${ccnr2_hex}";

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
