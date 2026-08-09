#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [1, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift // random_string (16);
  my $params = shift // "j9T";

  my $salt_b64 = _yescrypt_encode64 ($salt);
  my $setting = "\$y\$" . $params . "\$" . $salt_b64 . "\$";

  my $hash = crypt ($word, $setting);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 3) eq '$y$');

  my $idx = rindex ($line, ':');

  return if ($idx < 1);

  my $hash_str = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my @fields = split (/\$/, $hash_str);

  # ('', 'y', params, salt_b64, hash_b64)

  return unless (scalar @fields == 5);
  return unless ($fields[1] eq 'y');

  my $params = $fields[2];
  my $salt_b64 = $fields[3];

  my $salt = _yescrypt_decode64 ($salt_b64);

  return unless defined $salt;

  my $new_hash = module_generate_hash ($word, $salt, $params);

  return ($new_hash, $word);
}

sub _yescrypt_encode64
{
  my $data = shift;
  my @bytes = unpack ("C*", $data);
  my @itoa = split //, './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  my @result;
  my $i = 0;

  while ($i < scalar @bytes)
  {
    my $val = $bytes[$i]; $i++;
    my $bits = 8;

    if ($i < scalar @bytes)
    {
      $val |= $bytes[$i] << 8; $i++;
      $bits += 8;
    }

    if ($i < scalar @bytes)
    {
      $val |= $bytes[$i] << 16; $i++;
      $bits += 8;
    }

    while ($bits > 0)
    {
      push @result, $itoa[$val & 0x3f];
      $val >>= 6;
      $bits -= 6;
    }
  }

  return join ('', @result);
}

sub _yescrypt_decode64
{
  my $str = shift;
  my $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  my @chars = split //, $str;
  my @result;
  my $i = 0;

  while ($i < scalar @chars)
  {
    my $val = 0;
    my $bits = 0;

    while ($i < scalar @chars && $bits < 24)
    {
      my $c = index ($itoa64, $chars[$i]);

      return undef if ($c < 0);

      $val |= $c << $bits;
      $bits += 6;
      $i++;
    }

    while ($bits >= 8)
    {
      push @result, $val & 0xff;
      $val >>= 8;
      $bits -= 8;
    }
  }

  return pack ("C*", @result);
}

1;
