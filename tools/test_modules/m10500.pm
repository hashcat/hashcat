#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::RC4;
use Digest::MD5 qw (md5);

my $PDF_PADDING =
[
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56,
  0xff, 0xfa, 0x01, 0x08, 0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
];

sub module_constraints { [[0, 15], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub pdf_compute_encryption_key
{
  my $word_buf  = shift;
  my $padding   = shift;
  my $id        = shift;
  my $u         = shift;
  my $o         = shift;
  my $P         = shift;
  my $V         = shift;
  my $R         = shift;
  my $enc       = shift;

  ## start

  my $data;

  $data .= $word_buf;

  $data .= substr ($padding, 0, 32 - length $word_buf);

  $data .= pack ("H*", $o);
  $data .= pack ("I",  $P);
  $data .= pack ("H*", $id);

  if ($R >= 4)
  {
    if (!$enc)
    {
      $data .= pack ("I", -1);
    }
  }

  my $res = md5 ($data);

  if ($R >= 3)
  {
    for (my $i = 0; $i < 50; $i++)
    {
      $res = md5 ($res);
    }
  }

  return $res;
}

sub module_generate_hash
{
  my $word = shift;
  my $id   = shift;
  my $u    = shift;
  my $o    = shift;
  my $P    = shift;
  my $V    = shift;
  my $R    = shift;
  my $enc  = shift;

  if (defined $u == 0)
  {
    $u = "0" x 64;
  }

  my $u_save = $u;

  if (defined $o == 0)
  {
    $o = "0" x 64;
  }

  if (defined $R == 0)
  {
    $R = random_number (3, 4);
  }

  if (defined $V == 0)
  {
    $V = ($R == 3) ? 2 : 4;
  }

  if (defined $P == 0)
  {
    $P = ($R == 3) ? -4 : -1028;
  }

  if (defined $enc == 0)
  {
    $enc = ($R == 3) ? 1 : random_number (0, 1);
  }

  my $padding;

  for (my $i = 0; $i < 32; $i++)
  {
    $padding .= pack ("C", $PDF_PADDING->[$i]);
  }

  my $res = pdf_compute_encryption_key ($word, $padding, $id, $u, $o, $P, $V, $R, $enc);

  my $digest = md5 ($padding . pack ("H*", $id));

  my $m = Crypt::RC4->new ($res);

  $u = $m->RC4 ($digest);

  my @ress = split "", $res;

  for (my $x = 1; $x <= 19; $x++)
  {
    my @xor;

    for (my $i = 0; $i < 16; $i++)
    {
      $xor[$i] = chr (ord ($ress[$i]) ^ $x);
    }

    my $s = join ("", @xor);

    my $m2 = Crypt::RC4->new ($s);

    $u = $m2->RC4 ($u);
  }

  $u .= substr (pack ("H*", $u_save), 16, 16);

  my $hash = sprintf ('$pdf$%d*%d*128*%d*%d*16*%s*32*%s*32*%s', $V, $R, $P, $enc, $id, unpack ("H*", $u), $o);

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

  my $V        = shift @data; $V = substr ($V, 5, 1);
  my $R        = shift @data;
  return unless (shift @data eq '128');
  my $P        = shift @data;
  my $enc      = shift @data;
  return unless (shift @data eq '16');
  my $id       = shift @data;
  return unless (shift @data eq '32');
  my $u        = shift @data;
  return unless (shift @data eq '32');
  my $o        = shift @data;

  return unless defined $id;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $id, $u, $o, $P, $V, $R, $enc);

  return ($new_hash, $word);
}

1;
