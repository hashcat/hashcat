#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);

sub module_constraints { [[0, 232], [0, 232], [0, 32], [0, 28], [0, 32]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  # we need to reduce the maximum password and salt buffer size by 23 since we
  # add it here statically

  my $final = sprintf ("%s:Administration Tools:%s", $salt, $word);

  my $hash_buf = md5 ($final);

  my $res = "";

  for (my $pos = 0; $pos < 16; $pos += 2)
  {
    my $octet1 = ord (substr ($hash_buf, $pos + 0, 1));
    my $octet2 = ord (substr ($hash_buf, $pos + 1, 1));

    my $num = (($octet1 << 8) & 0xff00)
            | (($octet2 << 0) & 0x00ff);

    my $idx1 = $num >> 12 & 0x0f;
    my $idx2 = $num >>  6 & 0x3f;
    my $idx3 = $num       & 0x3f;

    my $itoa64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    $res = $res . substr ($itoa64, $idx1, 1) . substr ($itoa64, $idx2, 1) . substr ($itoa64, $idx3, 1);
  }

  my $obfuscate_str = "nrcstn";
  my @obfuscate_pos = (0, 6, 12, 17, 23, 29);

  foreach my $pos (keys @obfuscate_pos)
  {
    my $idx = $obfuscate_pos[$pos];

    my $before = substr ($res, 0, $idx);
    my $char   = substr ($obfuscate_str, $pos, 1);
    my $after  = substr ($res, $idx);

    $res = sprintf ("%s%s%s", $before, $char, $after);
  }

  my $hash = sprintf ("%s:%s", $res, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
