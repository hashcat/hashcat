#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);
use POSIX qw (ceil);

sub module_constraints { [[-1, -1], [-1, -1], [1, 31], [-1, -1], [-1, -1]] }

sub pseudo_base64
{
  my $itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  my $md5 = shift;
  my $s64 = "";
  for my $i (0..3) {
      my $v = unpack "V", substr ($md5, $i*4, 4);
      for (1..4) {
          $s64 .= substr ($itoa64, $v & 0x3f, 1);
          $v >>= 6;
      }
  }
  return $s64;
}

sub module_generate_hash
{
  my $word = shift;

  my $word_len = length ($word);

  my $pad_len = ceil ($word_len / 16) * 16;

  my $digest = md5 ($word . "\0" x ($pad_len - $word_len));

  my $hash = sprintf ("%s", pseudo_base64 ($digest));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed);

  return ($new_hash, $word);
}

1;
