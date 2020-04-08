#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::SHA1 qw (sha1);
use Crypt::Mode::ECB;

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

my $AES256_IGE_BLOCK_SIZE = 16;

#
# Helper functions:
#

sub exclusive_or
{
  my $in1 = shift;
  my $in2 = shift;

  # MIN () function (should always be 16 for us):
  # my $len = (length ($in1) <= length ($in2)) ? length ($in2) : length ($in1);

  # padding if input not multiple of block size:
  # $in1 .= "\x00" x ($AES256_IGE_BLOCK_SIZE - $len);
  # $in2 .= "\x00" x ($AES256_IGE_BLOCK_SIZE - $len);

  my $out = "";

  for (my $i = 0; $i < $AES256_IGE_BLOCK_SIZE; $i++) # $i < $len
  {
    $out .= chr (ord (substr ($in1, $i, 1)) ^ ord (substr ($in2, $i, 1)));
  }

  return $out;
}

sub aes256_encrypt_ige
{
  my $key = shift;
  my $iv  = shift;
  my $in  = shift;

  my $x_prev = substr ($iv, $AES256_IGE_BLOCK_SIZE, $AES256_IGE_BLOCK_SIZE);
  my $y_prev = substr ($iv,                      0, $AES256_IGE_BLOCK_SIZE);

  my $m = Crypt::Mode::ECB->new ('AES', 0);

  my $out = "";

  for (my $i = 0; $i < length ($in); $i += $AES256_IGE_BLOCK_SIZE)
  {
    my $x = substr ($in, $i, $AES256_IGE_BLOCK_SIZE);

    my $y_xor = exclusive_or ($x, $y_prev);

    my $y_final = $m->encrypt ($y_xor, $key);
    # $y_final .= "\x00" x ($AES256_IGE_BLOCK_SIZE - length ($y_final));

    my $y = exclusive_or ($y_final, $x_prev);

    $x_prev = $x;
    $y_prev = $y;

    $out .= $y;
  }

  return $out;
}

sub aes256_decrypt_ige
{
  my $key = shift;
  my $iv  = shift;
  my $in  = shift;

  my $x_prev = substr ($iv,                      0, $AES256_IGE_BLOCK_SIZE);
  my $y_prev = substr ($iv, $AES256_IGE_BLOCK_SIZE, $AES256_IGE_BLOCK_SIZE);

  my $m = Crypt::Mode::ECB->new ('AES', 0);

  my $out = "";

  for (my $i = 0; $i < length ($in); $i += $AES256_IGE_BLOCK_SIZE)
  {
    my $x = substr ($in, $i, $AES256_IGE_BLOCK_SIZE);

    my $y_xor = exclusive_or ($x, $y_prev);

    my $y_final = $m->decrypt ($y_xor, $key);
    # $y_final .= "\x00" x ($AES256_IGE_BLOCK_SIZE - length ($y_final));

    my $y = exclusive_or ($y_final, $x_prev);

    $x_prev = $x;
    $y_prev = $y;

    $out .= $y;
  }

  return $out;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 4000;
  my $data = shift;

  my $pbkdf = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 136
  );

  my $authkey = $pbkdf->PBKDF2 ($salt, $word);

  my $message     = "";
  my $message_key = "";

  if (defined ($data))
  {
    $message     = substr ($data, 16);
    $message_key = substr ($data,  0, 16);
  }
  else
  {
    $message     = random_bytes (272);
    $message_key = substr (sha1 ($message), 0, 16);
  }

  my $data_a = "\x00" x 48;
  my $data_b = "\x00" x 48;
  my $data_c = "\x00" x 48;
  my $data_d = "\x00" x 48;

  substr ($data_a,  0, 16) = $message_key; # memcpy ()
  substr ($data_b, 16, 16) = $message_key;
  substr ($data_c, 32, 16) = $message_key;
  substr ($data_d,  0, 16) = $message_key;

  substr ($data_a, 16, 32) = substr ($authkey,   8, 32);
  substr ($data_b,  0, 16) = substr ($authkey,  40, 16);
  substr ($data_b, 32, 16) = substr ($authkey,  56, 16);
  substr ($data_c,  0, 32) = substr ($authkey,  72, 32);
  substr ($data_d, 16, 32) = substr ($authkey, 104, 32);

  my $sha1_a = sha1 ($data_a);
  my $sha1_b = sha1 ($data_b);
  my $sha1_c = sha1 ($data_c);
  my $sha1_d = sha1 ($data_d);

  my $aes_key = substr ($sha1_a, 0,  8) . #  8 +
                substr ($sha1_b, 8, 12) . # 12 +
                substr ($sha1_c, 4, 12);  # 12 = 32

  my $aes_iv = substr ($sha1_a,  8, 12) . # 12 +
               substr ($sha1_b,  0,  8) . #  8 +
               substr ($sha1_c, 16,  4) . #  4 +
               substr ($sha1_d,  0,  8);  #  8 = 32

  my $enc_data = "";

  if (defined ($data))
  {
    # AES256 IGE decrypt:

    my $dec_data = aes256_decrypt_ige ($aes_key, $aes_iv, $message);

    my $h = substr (sha1 ($dec_data), 0, 16);

    if ($h eq $message_key)
    {
      $enc_data = $data;
    }
  }
  else
  {
    # AES256 IGE encrypt:

    my $enc_random_data = aes256_encrypt_ige ($aes_key, $aes_iv, $message);

    $enc_data = $message_key . $enc_random_data;
  }

  my $hash = sprintf ("\$telegram\$1*%i*%s*%s", $iter, unpack ("H*", $salt), unpack ("H*", $enc_data));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return if ($idx == -1);

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless defined $hash;
  return unless defined $word;

  my $signature = substr ($hash, 0, 10);

  return unless ($signature eq "\$telegram\$");

  my $version = substr ($hash, 10, 1);

  return unless ($version eq "1");

  my @split = split ('\*', $hash);

  return unless scalar @split == 4;

  shift @split;

  my $iter = shift @split;
  my $salt = shift @split;
  my $data = shift @split;

  return unless length ($salt) ==  64;
  return unless length ($data) == 576;

  $salt = pack ("H*", $salt);
  $data = pack ("H*", $data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter, $data);

  return ($new_hash, $word);
}

1;
