#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);

sub module_constraints { [[0, 255], [0, 16], [0, 15], [0, 16], [-1, -1]] }

sub to64
{
  my $v = shift;
  my $n = shift;

  my $itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  my $ret = "";

  while (($n - 1) >= 0)
  {
    $n = $n - 1;

    $ret .= substr ($itoa64, $v & 0x3f, 1);

    $v = $v >> 6;
  }

  return $ret
}

sub sha256_crypt
{
  my $iter = shift;
  my $pass = shift;
  my $salt = shift;

  my $hash = ""; # hash to be returned by this function

  my $final = sha256 ($pass . $salt . $pass);

  $salt = substr ($salt, 0, 16);

  my $tmp = $pass . $salt;

  my $pass_len = length ($pass);
  my $salt_len = length ($salt);

  my $i;

  for ($i = $pass_len; $i > 0; $i -= 16)
  {
    my $len = 16;

    if ($i < $len)
    {
      $len = $i;
    }

    $tmp .= substr ($final, 0, $len);
  }

  $i = $pass_len;

  while ($i > 0)
  {
    if ($i & 1)
    {
      $tmp .= $final;
    }
    else
    {
      $tmp .= $pass;
    }

    $i >>= 1;
  }

  $final = sha256 ($tmp);

  # p_bytes

  my $p_bytes = "";

  for ($i = 0; $i < $pass_len; $i++)
  {
    $p_bytes .= $pass;
  }

  $p_bytes = sha256 ($p_bytes);
  $p_bytes = substr ($p_bytes, 0, $pass_len);

  # s_bytes

  my $final_first_byte = ord (substr ($final, 0, 1));

  my $s_bytes = "";

  for ($i = 0; $i < (16 + $final_first_byte); $i++)
  {
    $s_bytes .= $salt;
  }

  $s_bytes = sha256 ($s_bytes);
  $s_bytes = substr ($s_bytes, 0, $salt_len);

  for ($i = 0; $i < $iter; $i++)
  {
    $tmp = "";

    if ($i & 1)
    {
      $tmp .= $p_bytes;
    }
    else
    {
      $tmp .= $final;
    }

    if ($i % 3)
    {
      $tmp .= $s_bytes;
    }

    if ($i % 7)
    {
      $tmp .= $p_bytes;
    }

    if ($i & 1)
    {
      $tmp .= $final;
    }
    else
    {
      $tmp .= $p_bytes;
    }

    $final = sha256 ($tmp);
  }

  # done
  # now format the output string ("hash")

  my $hash_buf;

  $hash .= to64 ((ord (substr ($final,  0, 1)) << 16) | (ord (substr ($final, 10, 1)) << 8) | (ord (substr ($final, 20, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 21, 1)) << 16) | (ord (substr ($final,  1, 1)) << 8) | (ord (substr ($final, 11, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 12, 1)) << 16) | (ord (substr ($final, 22, 1)) << 8) | (ord (substr ($final,  2, 1))), 4);
  $hash .= to64 ((ord (substr ($final,  3, 1)) << 16) | (ord (substr ($final, 13, 1)) << 8) | (ord (substr ($final, 23, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 24, 1)) << 16) | (ord (substr ($final,  4, 1)) << 8) | (ord (substr ($final, 14, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 15, 1)) << 16) | (ord (substr ($final, 25, 1)) << 8) | (ord (substr ($final,  5, 1))), 4);
  $hash .= to64 ((ord (substr ($final,  6, 1)) << 16) | (ord (substr ($final, 16, 1)) << 8) | (ord (substr ($final, 26, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 27, 1)) << 16) | (ord (substr ($final,  7, 1)) << 8) | (ord (substr ($final, 17, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 18, 1)) << 16) | (ord (substr ($final, 28, 1)) << 8) | (ord (substr ($final,  8, 1))), 4);
  $hash .= to64 ((ord (substr ($final,  9, 1)) << 16) | (ord (substr ($final, 19, 1)) << 8) | (ord (substr ($final, 29, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 31, 1)) <<  8) | (ord (substr ($final, 30, 1))), 3);

  my $magic = '$5$';

  if ($iter == 5000) # default
  {
    $hash_buf = sprintf ("%s%s\$%s", $magic, $salt , $hash);
  }
  else
  {
    $hash_buf = sprintf ("%srounds=%i\$%s\$%s", $magic, $iter, $salt , $hash);
  }

  return $hash_buf;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 5000;

  my $hash_buf = sha256_crypt ($iter, $word, $salt);

  my $hash = sprintf ("%s", $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":", 30);

  return if $index1 < 1;

  my $hash_in = substr ($line, 0, $index1);

  my $word = substr ($line, $index1 + 1);

  $index1 = index ($hash_in,  ",", 1);

  my $index2 = index ($hash_in, "\$", 1);

  if ($index1 != -1)
  {
    if ($index1 < $index2)
    {
      $index2 = $index1;
    }
  }

  #$param = substr ($hash_in, $index2, 1);

  $index2++;

  # rounds= if available
  my $iter;

  if (substr ($hash_in, $index2, 7) eq "rounds=")
  {
    my $old_index = $index2;

    $index2 = index ($hash_in, "\$", $index2 + 1);

    return if $index2 < 1;

    $iter = substr ($hash_in, $old_index + 7, $index2 - $old_index - 7);

    $index2++;
  }

  # get salt
  my $index3 = rindex ($hash_in, "\$");

  return if $index3 < 1;

  my $salt = substr ($hash_in, $index2, $index3 - $index2);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;

