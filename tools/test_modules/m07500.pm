#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Encode;
use Crypt::RC4;
use Digest::HMAC_MD5 qw (hmac_md5);
use Digest::MD4      qw (md4);
use POSIX            qw (strftime);

sub get_random_kerberos5_salt
{
  my $custom_salt = shift;

  my $clear_data = random_bytes (14) .
                   strftime ("%Y%m%d%H%M%S", localtime) .
                   random_bytes (8);

  my $user  = "user";
  my $realm = "realm";
  my $salt  = "salt";

  my $salt_buf = $user . "\$" . $realm . "\$" . $salt . "\$" . unpack ("H*", $custom_salt) . "\$" . unpack ("H*", $clear_data) . "\$";

  return $salt_buf;
}

sub module_constraints { [[0, 256], [16, 16], [0, 27], [16, 16], [-1, -1]] }

sub module_generate_hash
{
  my $word_buf = shift;
  my $salt_buf = shift;

  if ($salt_buf !~ /\$/)
  {
    $salt_buf = get_random_kerberos5_salt ($salt_buf);
  }

  my @salt_arr = split ("\\\$", $salt_buf);

  my $user = $salt_arr[0];

  my $realm = $salt_arr[1];

  my $salt = $salt_arr[2];

  my $hmac_salt = $salt_arr[3];
  my $hmac_salt_bin = pack ("H*", $hmac_salt);

  my $clear_data = $salt_arr[4];

  my $k = md4 (encode ("UTF-16LE", $word_buf));

  my $k1 = hmac_md5 ("\x01\x00\x00\x00", $k);

  my $k3 = hmac_md5 ($hmac_salt_bin, $k1);

  my $hash_buf;

  if (length ($clear_data) > 1)
  {
    my $clear_data_bin = pack ("H*", $clear_data);

    $hash_buf = RC4 ($k3, $clear_data_bin);
  }
  else
  {
    my $hash = $salt_arr[5];

    my $hash_bin = pack ("H*", $hash);

    my $clear_data = RC4 ($k3, $hash_bin);

    my $timestamp = substr ($clear_data, 14, 14);

    my $is_numeric = 1;

    if ($timestamp !~ /^[[:digit:]]{14}$/)
    {
      $is_numeric = 0;
    }

    if (! $is_numeric)
    {
      $hash_buf = "\x00" x 36;

      if ($hash_buf eq $hash_bin)
      {
        $hash_buf = "\x01" x 36;
      }
    }
    else
    {
      $hash_buf = $hash_bin;
    }
  }

  my $tmp_hash = sprintf ("\$krb5pa\$23\$%s\$%s\$%s\$%s%s", $user, $realm, $salt, unpack ("H*", $hash_buf), $hmac_salt);

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, "\$", 11);

  return if $index1 < 1;

  my $index2 = index ($line, "\$", $index1 + 1);

  return if $index2 < 1;

  my $index3 = index ($line, "\$", $index2 + 1);

  return if $index3 < 1;

  $index2 = index ($line, ":", $index3 + 1);

  return if $index2 < 1;

  my $hash_in = substr ($line, 0, $index2);
  my $word    = substr ($line, $index2 + 1);

  my $salt;

  $salt  = substr ($hash_in, 11, $index3 - 10);
  $salt .= substr ($hash_in, $index2 - 32) . "\$\$";
  $salt .= substr ($hash_in, $index3 + 1, $index2 - $index3 - 32 - 1);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
