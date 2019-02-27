#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 1000;

  my $data;

  $data .= $salt;
  $data .= $word x $iter;
  $data .= $word;

  my $digest = md5_hex ($data);

  my $hash;

  if ($iter == 1000)
  {
    $hash = sprintf ("\@m\@%s\@%s", $digest, $salt);
  }
  else
  {
    $hash = sprintf ("\@m,%u\@%s\@%s", $iter, $digest, $salt);
  }

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my (undef, $tag, $digest, $salt) = split (/\@/, $hash);

  my ($type, $iter) = split (/\,/, $tag);

  return unless ($type eq "m");

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

1;
