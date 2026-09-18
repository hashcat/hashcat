#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::RC4;

my $PDF_PADDING =
[
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56,
  0xff, 0xfa, 0x01, 0x08, 0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
];

sub module_constraints { [[-1, -1], [-1, -1], [5, 5], [32, 32], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $id   = shift;
  my $u    = shift;
  my $o    = shift;
  my $P    = shift;

  ## the candidate of this collider mode is the RC4-40 key itself, so it is
  ## always exactly 5 bytes long

  return unless defined $word;
  return unless length ($word) == 5;

  if (defined $id == 0)
  {
    $id = random_hex_string (32);
  }

  if (defined $o == 0)
  {
    $o = "0" x 64;
  }

  if (defined $P == 0)
  {
    $P = -1;
  }

  my $padding;

  for (my $i = 0; $i < 32; $i++)
  {
    $padding .= pack ("C", $PDF_PADDING->[$i]);
  }

  ## mode 10400 derives the RC4 key from the password with MD5, this mode skips
  ## that step: the U value is the padding encrypted with the candidate itself,
  ## and the first 16 bytes of it are the digest the kernel compares

  my $m = Crypt::RC4->new ($word);

  $u = $m->RC4 ($padding);

  my $hash = sprintf ('$pdf$%d*%d*40*%d*%d*16*%s*32*%s*32*%s', 1, 2, $P, 0, $id, unpack ("H*", $u), $o);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split /\*/, $hash_in;

  return unless scalar @data == 11;

  return unless (shift @data eq '$pdf$1');
  return unless (shift @data eq '2');
  return unless (shift @data eq '40');
  my $P        = shift @data;
  return unless (shift @data eq '0');
  return unless (shift @data eq '16');
  my $id       = shift @data;
  return unless (shift @data eq '32');
  my $u        = shift @data;
  return unless (shift @data eq '32');
  my $o        = shift @data;

  my $salt   = $id;
  my $param  = $u;
  my $param2 = $o;
  my $param3 = $P;

  return unless defined $salt;
  return unless defined $word;

  ## the plain of this mode is always hexified: src/outfile.c forces OUTFILE_FMT_HASH |
  ## OUTFILE_FMT_HEXPLAIN for every OPTS_TYPE_PT_ALWAYS_HEXIFY mode and src/potfile.c strips
  ## the "$HEX[" and the "]" for a collider mode, so a real crack line carries the 5 byte key
  ## as 10 bare hex digits. it is unhexified for the computation and returned in the form it
  ## came in, the way m00000.pm does it, because test.pl compares the returned pair against
  ## the line it read

  my $word_packed = pack_if_HEX_notation ($word);

  if ($word_packed =~ m/^[0-9a-fA-F]{10}$/)
  {
    $word_packed = pack ("H*", $word_packed);
  }

  return unless length ($word_packed) == 5;

  my $new_hash = module_generate_hash ($word_packed, $salt, $param, $param2, $param3);

  return ($new_hash, $word);
}

1;
