#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Digest::CRC qw (crc32);
use Digest::SHA qw (sha256);
use Encode;

sub module_constraints { [[0, 256], [0, 16], [0, 20], [0, 16], [-1, -1]] }

sub module_generate_hash
{
  my $word_buf          = shift;
  my $salt_buf          = shift;
  my $iter              = shift;
  my $additional_param  = shift;
  my $additional_param2 = shift;
  my $additional_param3 = shift;
  my $additional_param4 = shift;
  my $additional_param5 = shift;
  my $additional_param6 = shift;

  my ($p, $num_cycle_power, $seven_zip_salt_len, $seven_zip_salt_buf, $salt_len, $data_len, $unpack_size, $data_buf);

  $p = 0; # is fixed

  my $validation_only = 0;

  $validation_only = 1 if (defined ($additional_param));

  if ($validation_only == 1)
  {
    $num_cycle_power = int ($iter);
    $seven_zip_salt_len = $additional_param;
    $seven_zip_salt_buf = $additional_param2;
    $salt_len = $additional_param3;
    # $salt_buf set in parser
    # $hash_buf (resulting crc)
    $data_len = $additional_param4;
    $unpack_size = $additional_param5;
    $data_buf = $additional_param6;
  }
  else
  {
    $num_cycle_power = 14; # by default it is 19
    $seven_zip_salt_len = 0;
    $seven_zip_salt_buf = "";
    $salt_len = length ($salt_buf);
    # $salt_buf set automatically
    # $hash_buf (resulting crc)
    # $data_len will be set when encrypting
    $unpack_size = random_number (1, 32 + 1);
    $data_buf = random_string ($unpack_size);
  }

  #
  # 2 ^ NumCyclesPower "iterations" of SHA256 (only one final SHA256)
  #

  $word_buf = encode ("UTF-16LE", $word_buf);

  my $rounds = 1 << $num_cycle_power;

  my $pass_buf = "";

  for (my $i = 0; $i < $rounds; $i++)
  {
    my $num_buf = "";

    $num_buf .= pack ("V", $i);
    $num_buf .= "\x00" x 4;

    # this would be better but only works on 64-bit systems:
    # $num_buf = pack ("q", $i);

    $pass_buf .= sprintf ("%s%s", $word_buf, $num_buf);
  }

  my $key = sha256 ($pass_buf);

  # the salt_buf is our IV for AES CBC
  # pad the salt_buf

  my $salt_buf_len = length ($salt_buf);
  my $salt_padding_len = 0;

  if ($salt_buf_len < 16)
  {
    $salt_padding_len = 16 - $salt_buf_len;
  }

  $salt_buf .= "\x00" x $salt_padding_len;

  my $aes = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    key         => $key,
    keysize     => 32,
    literal_key => 1,
    iv          => $salt_buf,
    header      => "none",
  });

  my $hash_buf;

  if ($validation_only == 1)
  {
    # decrypt

    my $decrypted_data = $aes->decrypt ($data_buf);

    $decrypted_data = substr ($decrypted_data, 0, $unpack_size);

    $hash_buf = crc32 ($decrypted_data);
  }
  else
  {
    # encrypt

    $hash_buf = crc32 ($data_buf);

    $data_buf = $aes->encrypt ($data_buf);

    $data_len = length ($data_buf);
  }

  my $tmp_hash = sprintf ("\$7z\$%i\$%i\$%i\$%s\$%i\$%08s\$%u\$%u\$%u\$%s", $p, $num_cycle_power, $seven_zip_salt_len, $seven_zip_salt_buf, $salt_len, unpack ("H*", $salt_buf), $hash_buf, $data_len, $unpack_size, unpack ("H*", $data_buf));

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 4) eq '$7z$');

  # p

  my $index1 = index ($line, '$', 4);

  return if $index1 < 0;

  my $p = substr ($line, 4, $index1 - 4);

  return unless ($p eq "0");

  # num cycle power

  my $index2 = index ($line, '$', $index1 + 1);

  return if $index2 < 0;

  my $iter = substr ($line, $index1 + 1, $index2 - $index1 - 1);

  # seven zip salt length

  $index1 = index ($line, '$', $index2 + 1);

  return if $index1 < 0;

  my $param = substr ($line, $index2 + 1, $index1 - $index2 - 1);

  # seven zip salt

  $index2 = index ($line, '$', $index1 + 1);

  return if $index2 < 0;

  my $param2 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

  # salt len

  $index1 = index ($line, '$', $index2 + 1);

  return if $index1 < 0;

  my $param3 = substr ($line, $index2 + 1, $index1 - $index2 - 1);

  # salt

  $index2 = index ($line, '$', $index1 + 1);

  return if $index2 < 0;

  my $salt = substr ($line, $index1 + 1, $index2 - $index1 - 1);

  $salt = pack ("H*", $salt);

  # crc / hash

  $index1 = index ($line, '$', $index2 + 1);

  return if $index1 < 0;

  my $crc = substr ($line, $index2 + 1, $index1 - $index2 - 1);

  # ignore this crc, we don't need to pass it to gen_hash ()

  # data len

  $index2 = index ($line, '$', $index1 + 1);

  return if $index2 < 0;

  my $param4 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

  # unpack size

  $index1 = index ($line, '$', $index2 + 1);

  return if $index1 < 0;

  my $param5 = substr ($line, $index2 + 1, $index1 - $index2 - 1);

  # data

  $index2 = index ($line, ':', $index1 + 1);

  return if $index2 < 0;

  my $param6 = substr ($line, $index1 + 1, $index2 - $index1 - 1);
  $param6 = pack ("H*", $param6);

  my $word = substr ($line, $index2 + 1);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter, $param, $param2, $param3, $param4, $param5, $param6);

  return ($new_hash, $word);
}

1;
