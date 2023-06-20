#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);
use POSIX       qw (ceil);

sub module_constraints { [[-1, -1], [-1, -1], [0, 47], [1, 4], [0, 48]] }

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
  my $salt = shift;

  my $word_salt = $word . $salt;

  my $word_salt_len = length ($word_salt);

  my $pad_len = ceil ($word_salt_len / 16) * 16;

  my $digest = md5 ($word_salt . "\0" x ($pad_len - $word_salt_len));

  my $hash = sprintf ("%s:%s", pseudo_base64 ($digest), $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
