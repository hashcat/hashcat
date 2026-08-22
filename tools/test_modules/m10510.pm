#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::RC4;
use Digest::MD5 qw (md5);

# PDF 1.3 - 1.6 (Acrobat 4 - 8) with a 40-bit RC4 key: the same standard
# security handler as m10500, with the key shortened from 16 bytes to 5. That
# one number changes three things, so they are kept in $KEY_LEN rather than
# spread through the code: the truncation inside the 50-round key hardening,
# the RC4 key itself, and the width of the XOR in the 19 U rounds.
#
# The parser accepts V 1 or 2 with R 3 only, and insists on a 40 in the bits
# field, so those are what module_generate_hash emits.

my $PDF_PADDING =
[
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56,
  0xff, 0xfa, 0x01, 0x08, 0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
];

my $KEY_LEN = 5; # 40 bits

sub module_constraints { [[0, 15], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub pdf_compute_encryption_key
{
  my $word_buf = shift;
  my $padding  = shift;
  my $id       = shift;
  my $o        = shift;
  my $P        = shift;

  my $data;

  $data .= $word_buf;
  $data .= substr ($padding, 0, 32 - length $word_buf);
  $data .= pack ("H*", $o);
  $data .= pack ("I",  $P);
  $data .= pack ("H*", $id);

  my $res = md5 ($data);

  # R 3 hardening, over the first $KEY_LEN bytes only
  for (my $i = 0; $i < 50; $i++)
  {
    $res = md5 (substr ($res, 0, $KEY_LEN));
  }

  return substr ($res, 0, $KEY_LEN);
}

sub module_generate_hash
{
  my $word = shift;
  my $id   = shift;
  my $u    = shift;
  my $o    = shift;
  my $P    = shift;
  my $V    = shift;

  if (defined $u == 0)
  {
    $u = "0" x 64;
  }

  my $u_save = $u;

  if (defined $o == 0)
  {
    $o = "0" x 64;
  }

  if (defined $P == 0)
  {
    $P = -4;
  }

  if (defined $V == 0)
  {
    $V = random_number (1, 2);
  }

  my $R = 3; # the only revision this mode parses

  my $padding;

  for (my $i = 0; $i < 32; $i++)
  {
    $padding .= pack ("C", $PDF_PADDING->[$i]);
  }

  my $key = pdf_compute_encryption_key ($word, $padding, $id, $o, $P);

  my $digest = md5 ($padding . pack ("H*", $id));

  my $m = Crypt::RC4->new ($key);

  $u = $m->RC4 ($digest);

  my @keys = split "", $key;

  for (my $x = 1; $x <= 19; $x++)
  {
    my @xor;

    for (my $i = 0; $i < $KEY_LEN; $i++)
    {
      $xor[$i] = chr (ord ($keys[$i]) ^ $x);
    }

    my $s = join ("", @xor);

    my $m2 = Crypt::RC4->new ($s);

    $u = $m2->RC4 ($u);
  }

  # only the first 16 bytes of U are checked; the rest is arbitrary padding
  $u .= substr (pack ("H*", $u_save), 16, 16);

  my $hash = sprintf ('$pdf$%d*%d*40*%d*1*16*%s*32*%s*32*%s', $V, $R, $P, $id, unpack ("H*", $u), $o);

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

  my $V = shift @data; $V = substr ($V, 5, 1);
  my $R = shift @data;
  return unless (shift @data eq '40');
  my $P = shift @data;
  shift @data; # enc_md, ignored for R 3
  return unless (shift @data eq '16');
  my $id = shift @data;
  return unless (shift @data eq '32');
  my $u = shift @data;
  return unless (shift @data eq '32');
  my $o = shift @data;

  return unless defined $id;
  return unless $R == 3;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $id, $u, $o, $P, $V);

  return ($new_hash, $word);
}

1;
