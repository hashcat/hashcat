#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1 sha1_hex);

sub module_constraints { [[-1, -1], [-1, -1], [0, 55], [1, 12], [0, 55]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $theMagicArray_s =
    "\x91\xac\x51\x14\x9f\x67\x54\x43\x24\xe7\x3b\xe0\x28\x74\x7b\xc2" .
    "\x86\x33\x13\xeb\x5a\x4f\xcb\x5c\x08\x0a\x73\x37\x0e\x5d\x1c\x2f" .
    "\x33\x8f\xe6\xe5\xf8\x9b\xae\xdd\x16\xf2\x4b\x8d\x2c\xe1\xd4\xdc" .
    "\xb0\xcb\xdf\x9d\xd4\x70\x6d\x17\xf9\x4d\x42\x3f\x9b\x1b\x11\x94" .
    "\x9f\x5b\xc1\x9b\x06\x05\x9d\x03\x9d\x5e\x13\x8a\x1e\x9a\x6a\xe8" .
    "\xd9\x7c\x14\x17\x58\xc7\x2a\xf6\xa1\x99\x63\x0a\xd7\xfd\x70\xc3" .
    "\xf6\x5e\x74\x13\x03\xc9\x0b\x04\x26\x98\xf7\x26\x8a\x92\x93\x25" .
    "\xb0\xa2\x0d\x23\xed\x63\x79\x6d\x13\x32\xfa\x3c\x35\x02\x9a\xa3" .
    "\xb3\xdd\x8e\x0a\x24\xbf\x51\xc3\x7c\xcd\x55\x9f\x37\xaf\x94\x4c" .
    "\x29\x08\x52\x82\xb2\x3b\x4e\x37\x9f\x17\x07\x91\x11\x3b\xfd\xcd";

  $salt = uc $salt;

  my $digest = sha1 ($word . $salt);

  my ($a, $b, $c, $d, $e) = unpack ("I*", $digest);

  my $lengthMagicArray = 0x20;
  my $offsetMagicArray = 0;

  $lengthMagicArray += (($a >>  0) & 0xff) % 6;
  $lengthMagicArray += (($a >>  8) & 0xff) % 6;
  $lengthMagicArray += (($a >> 16) & 0xff) % 6;
  $lengthMagicArray += (($a >> 24) & 0xff) % 6;
  $lengthMagicArray += (($b >>  0) & 0xff) % 6;
  $lengthMagicArray += (($b >>  8) & 0xff) % 6;
  $lengthMagicArray += (($b >> 16) & 0xff) % 6;
  $lengthMagicArray += (($b >> 24) & 0xff) % 6;
  $lengthMagicArray += (($c >>  0) & 0xff) % 6;
  $lengthMagicArray += (($c >>  8) & 0xff) % 6;
  $offsetMagicArray += (($c >> 16) & 0xff) % 8;
  $offsetMagicArray += (($c >> 24) & 0xff) % 8;
  $offsetMagicArray += (($d >>  0) & 0xff) % 8;
  $offsetMagicArray += (($d >>  8) & 0xff) % 8;
  $offsetMagicArray += (($d >> 16) & 0xff) % 8;
  $offsetMagicArray += (($d >> 24) & 0xff) % 8;
  $offsetMagicArray += (($e >>  0) & 0xff) % 8;
  $offsetMagicArray += (($e >>  8) & 0xff) % 8;
  $offsetMagicArray += (($e >> 16) & 0xff) % 8;
  $offsetMagicArray += (($e >> 24) & 0xff) % 8;

  my $hash_buf = sha1_hex ($word . substr ($theMagicArray_s, $offsetMagicArray, $lengthMagicArray) . $salt);

  my $hash = sprintf ("%s\$%.20s%020X", $salt, uc $hash_buf, 0);

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
