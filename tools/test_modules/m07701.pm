#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);

sub module_constraints { [[-1, -1], [-1, -1], [0, 8], [1, 12], [0, 55]] }

sub sapb_transcode
{
  my $data_s = shift;

  my @data = split "", $data_s;

  my $transTable_s =
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\x3f\x40\x41\x50\x43\x44\x45\x4b\x47\x48\x4d\x4e\x54\x51\x53\x46" .
    "\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x56\x55\x5c\x49\x5d\x4a" .
    "\x42\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" .
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x58\x5b\x59\xff\x52" .
    "\x4c\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" .
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x57\x5e\x5a\x4f\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

  my @transTable = unpack ("C256", $transTable_s);

  my @out;

  for (my $i = 0; $i < scalar @data; $i++)
  {
    $out[$i] = $transTable[int (ord ($data[$i]))];
  }

  return pack ("C*", @out);
}

sub sapb_waldorf
{
  my $digest_s = shift;

  my $w_s = shift;
  my $s_s = shift;

  my @w = unpack "C*", $w_s;
  my @s = unpack "C*", $s_s;

  my $bcodeTable_s =
    "\x14\x77\xf3\xd4\xbb\x71\x23\xd0\x03\xff\x47\x93\x55\xaa\x66\x91" .
    "\xf2\x88\x6b\x99\xbf\xcb\x32\x1a\x19\xd9\xa7\x82\x22\x49\xa2\x51" .
    "\xe2\xb7\x33\x71\x8b\x9f\x5d\x01\x44\x70\xae\x11\xef\x28\xf0\x0d";

  my @bcodeTable = unpack ("C48", $bcodeTable_s);

  my @abcd = unpack ("C16", $digest_s);

  my $sum20 = ($abcd[0] & 3)
            + ($abcd[1] & 3)
            + ($abcd[2] & 3)
            + ($abcd[3] & 3)
            + ($abcd[5] & 3);

  $sum20 |= 0x20;

  my @out;

  for (my $i2 = 0; $i2 < $sum20; $i2++)
  {
    $out[$i2] = 0;
  }

  for (my $i1 = 0, my $i2 = 0, my $i3 = 0; $i2 < $sum20; $i2++, $i2++)
  {
    if ($i1 < length $w_s)
    {
      if ($abcd[15 - $i1] & 1)
      {
        $out[$i2] = $bcodeTable[48 - 1 - $i1];

        $i2++;
      }

      $out[$i2] = $w[$i1];

      $i1++;
      $i2++;
    }

    if ($i3 < length $s_s)
    {
      $out[$i2] = $s[$i3];

      $i2++;
      $i3++;
    }

    $out[$i2] = $bcodeTable[$i2 - $i1 - $i3];
  }

  return substr (pack ("C*", @out), 0, $sum20);
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  $word = uc $word;
  $salt = uc $salt;

  my $word_buf_t = sapb_transcode ($word);
  my $salt_buf_t = sapb_transcode ($salt);

  my $digest1 = md5 ($word_buf_t . $salt_buf_t);

  my $data = sapb_waldorf ($digest1, $word_buf_t, $salt_buf_t);

  my $digest2 = md5 ($data);

  my ($a, $b, $c, $d) = unpack ("N4", $digest2);

  $a ^= $c;
  $b ^= $d;

  my $hash = sprintf ("%s\$%08X%08X", $salt, $a, 0);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my @split1 = split (":", $line);

  my @split2 = split ('\$', $split1[0]);

  return unless scalar @split2 == 2;

  my $word;

  if (scalar @split1 > 1)
  {
    $word = $split1[1];
  }
  else
  {
    $word = "";
  }

  my $salt = $split2[0];

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;

