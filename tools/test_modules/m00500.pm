#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);

sub module_constraints { [[0, 256], [0, 8], [0, 15], [0, 8], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  my $iterations = 1000;

  if (defined ($iter))
  {
    if ($iter > 0)
    {
      $iterations = int ($iter);
    }
  }

  my $hash_buf = md5_crypt ('$1$', $iterations, $word, $salt);

  return $hash_buf;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $index1 = index ($hash, ',', 1);
  my $index2 = index ($hash, '$', 1);

  if ($index1 != -1)
  {
    if ($index1 < $index2)
    {
      $index2 = $index1;
    }
  }

  $index2++;

  # rounds= if available
  my $iter = 0;

  if (substr ($hash, $index2, 7) eq "rounds=")
  {
    my $old_index = $index2;

    $index2 = index ($hash, '$', $index2 + 1);

    return if $index2 < 1;

    $iter = substr ($hash, $old_index + 7, $index2 - $old_index - 7);

    $index2++;
  }

  # get salt
  my $index3 = rindex ($hash, '$');

  return if $index3 < 1;

  my $salt = substr ($hash, $index2, $index3 - $index2);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

sub md5_crypt
{
  my $magic = shift;

  my $iter = shift;
  my $pass = shift;
  my $salt = shift;

  my $hash = ""; # hash to be returned by this function

  my $final = md5 ($pass . $salt . $pass);

  $salt = substr ($salt, 0, 8);

  my $tmp = $pass . $magic . $salt;

  my $pass_len = length ($pass);

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
      $tmp .= chr (0);
    }
    else
    {
      $tmp .= substr ($pass, 0, 1);
    }

    $i >>= 1;
  }

  $final = md5 ($tmp);

  for ($i = 0; $i < $iter; $i++)
  {
    $tmp = "";

    if ($i & 1)
    {
      $tmp .= $pass;
    }
    else
    {
      $tmp .= $final;
    }

    if ($i % 3)
    {
      $tmp .= $salt;
    }

    if ($i % 7)
    {
      $tmp .= $pass;
    }

    if ($i & 1)
    {
      $tmp .= $final;
    }
    else
    {
      $tmp .= $pass;
    }

    $final = md5 ($tmp);
  }

  # done
  # now format the output sting ("hash")

  my $hash_buf;

  $hash  = to64 ((ord (substr ($final, 0, 1)) << 16) | (ord (substr ($final,  6, 1)) << 8) | (ord (substr ($final, 12, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 1, 1)) << 16) | (ord (substr ($final,  7, 1)) << 8) | (ord (substr ($final, 13, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 2, 1)) << 16) | (ord (substr ($final,  8, 1)) << 8) | (ord (substr ($final, 14, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 3, 1)) << 16) | (ord (substr ($final,  9, 1)) << 8) | (ord (substr ($final, 15, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 4, 1)) << 16) | (ord (substr ($final, 10, 1)) << 8) | (ord (substr ($final,  5, 1))), 4);
  $hash .= to64 (ord (substr ($final, 11, 1)), 2);

  if ($iter == 1000) # default
  {
    $hash_buf = sprintf ("%s%s\$%s", $magic , $salt , $hash);
  }
  else
  {
    $hash_buf = sprintf ("%srounds=%i\$%s\$%s", $magic, $iter, $salt , $hash);
  }

  return $hash_buf;
}

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

1;
