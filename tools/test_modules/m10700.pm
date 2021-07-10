#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Digest::SHA qw (sha256 sha384 sha512);

sub module_constraints { [[1, 127], [32, 32], [1, 15], [32, 32], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $id   = shift;
  my $rest = shift;

  if (defined $id == 0)
  {
    $id = "0" x 32;
  }

  if (defined $rest == 0)
  {
    $rest = "127*";
    $rest .= "0" x 64;
    $rest .= $id;
    $rest .= "0" x 158;
    $rest .= "*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000";
  }

  my @datax = split /\*/, $rest;

  my $u = pack ("H*", $datax[1]);

  my $block = sha256 ($word . substr ($u, 32, 8));

  my $block_size = 32;

  my $data = 0x00 x 64;

  my $data_len = 1;

  my $data63 = 0;

  for (my $i = 0; $i < 64 || $i < $data63 + 32; $i++)
  {
    $data = $word . $block;

    $data_len = length ($data);

    for (my $k = 1; $k < 64; $k++)
    {
      $data .= $word . $block;
    }

    my $aes = Crypt::CBC->new ({
      key         => substr ($block,  0, 16),
      cipher      => "Crypt::Rijndael",
      iv          => substr ($block, 16, 16),
      literal_key => 1,
      header      => "none",
      keysize     => 16,
      padding     => "none",
    });

    my $data = $aes->encrypt ($data);

    my $sum = 0;

    for (my $j = 0; $j < 16; $j++)
    {
      $sum += ord (substr ($data, $j, 1));
    }

    $block_size = 32 + ($sum % 3) * 16;

    if ($block_size == 32)
    {
      $block = sha256 (substr ($data, 0, $data_len * 64));
    }
    elsif ($block_size == 48)
    {
      $block = sha384 (substr ($data, 0, $data_len * 64));
    }
    elsif ($block_size == 64)
    {
      $block = sha512 (substr ($data, 0, $data_len * 64));
    }

    $data63 = ord (substr ($data, $data_len * 64 - 1, 1));
  }

  $datax[1] = unpack ("H*", substr ($block, 0, 32) . substr ($u, 32));

  $rest = join ("*", @datax);

  my $hash = sprintf ('$pdf$5*6*256*-1028*1*16*%s*%s', $id, $rest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # PDF 1.7 Level 8 (Acrobat 10 - 11)
  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split /\*/, $hash_in;

  return unless scalar @data >= 11;

  return unless (shift @data eq '$pdf$5');
  return unless (shift @data eq '6');
  return unless (shift @data eq '256');
  return unless (shift @data eq '-1028');
  return unless (shift @data eq '1');
  return unless (shift @data eq '16');

  my $id   = shift @data;
  my $rest = join "*", @data;

  return unless defined $id;
  return unless defined $rest;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $id, $rest);

  return ($new_hash, $word);
}

1;
