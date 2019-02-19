#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);

sub module_constraints { [[0, 127], [32, 32], [0, 31], [32, 32], [-1, -1]] }

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

  my @data = split /\*/, $rest;

  my $u = pack ("H*", $data[1]);

  my $h = sha256 ($word . substr ($u, 32, 8));

  $data[1] = unpack ("H*", $h . substr ($u, 32));

  $rest = join ("*", @data);

  my $hash = sprintf ('$pdf$5*5*256*-1028*1*16*%s*%s', $id, $rest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # PDF 1.7 Level 3 (Acrobat 9)
  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split /\*/, $hash_in;

  return unless scalar @data >= 11;

  return unless (shift @data eq '$pdf$5');
  return unless (shift @data eq '5');
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
