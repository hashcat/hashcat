#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);

sub module_constraints { [[-1, -1], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

my $itoa62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

sub module_generate_hash
{
  my $word = shift;

  my $digest = md5 ($word);

  my @chksum;

  for (my $i = 0, my $j = 0; $i < 16; $i += 2, $j += 1)
  {
    $chksum[$j] = (ord (substr ($digest, $i + 0, 1)) + ord (substr ($digest, $i + 1, 1))) % 62;

    $chksum[$j] = substr ($itoa62, $chksum[$j], 1);
  }

  my $res = join "", @chksum;

  my $hash = sprintf ("%s", $res);

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
