#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

my $ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

sub module_constraints { [[0, 256], [1, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift // random_string (12);

  # the self-test configuration of a scrypt mode is fixed, so N, r and p have
  # to stay at the values the module ships with
  my $n_log2 = shift // 14;
  my $r = shift // 8;
  my $p = shift // 1;

  my $setting = "\$7\$" . substr ($ITOA64, $n_log2, 1)
              . _encode_uint ($r, 5)
              . _encode_uint ($p, 5)
              . $salt . "\$";

  my $hash = crypt ($word, $setting);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 3) eq '$7$');

  my $idx = rindex ($line, ':');

  return if ($idx < 1);

  my $hash_str = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my @fields = split (/\$/, $hash_str);

  # ('', '7', params . salt, hash)

  return unless (scalar @fields == 4);
  return unless ($fields[1] eq '7');

  my $setting = $fields[2];

  return unless (length ($setting) > 11);

  my $n_log2 = index ($ITOA64, substr ($setting, 0, 1));

  return if ($n_log2 < 0);

  my $r = _decode_uint (substr ($setting, 1, 5));
  my $p = _decode_uint (substr ($setting, 6, 5));

  return unless defined $r;
  return unless defined $p;

  my $salt = substr ($setting, 11);

  my $new_hash = module_generate_hash ($word, $salt, $n_log2, $r, $p);

  return ($new_hash, $word);
}

# the integers are little-endian 6-bit groups in the crypt alphabet

sub _encode_uint
{
  my $value = shift;
  my $len = shift;

  my $out = '';

  for (my $i = 0; $i < $len; $i++)
  {
    $out .= substr ($ITOA64, ($value >> (6 * $i)) & 0x3f, 1);
  }

  return $out;
}

sub _decode_uint
{
  my $str = shift;

  my $value = 0;

  my @chars = split //, $str;

  for (my $i = 0; $i < scalar @chars; $i++)
  {
    my $c = index ($ITOA64, $chars[$i]);

    return undef if ($c < 0);

    $value |= $c << (6 * $i);
  }

  return $value;
}

1;
