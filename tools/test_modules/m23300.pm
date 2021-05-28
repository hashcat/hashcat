#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);
use Crypt::PBKDF2;
use Crypt::CBC;

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word     = shift;
  my $salt     = shift;
  my $hash_ver = shift;
  my $file_ver = shift;
  my $iter     = shift;
  my $iv       = shift;
  my $data     = shift;

  my $FORMAT = 1;

  my $is_decrypt = defined ($data);

  if ($is_decrypt == 0)
  {
    my $type = random_number (1, 2);

    if ($type == 1)
    {
      $hash_ver = 1;
      $file_ver = 2;

      $iter = 100000;
      $salt = substr ($salt, 0, 32); # full one
    }
    else
    {
      $hash_ver = 2;
      $file_ver = 1;

      $iter = 4000;
      $salt = substr ($salt, 0, 16);
    }

    $salt = pack ("H*", $salt);

    $iv   = random_bytes (16);
    $data = random_bytes (32);

    $data .= sha256 ($data);
  }

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
    iterations => $iter,
    output_len => 16,
  );

  my $key = $pbkdf2->PBKDF2 ($salt, $word);

  # AES-CBC

  my $cipher = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    key         => $key,
    iv          => $iv,
    keysize     => 16,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  if ($is_decrypt == 1)
  {
    my $hash_data = $data;

    $data = "WRONG";

    my $decrypted = $cipher->decrypt ($hash_data);

    my $raw_data = substr ($decrypted,  0, 32);
    my $checksum = substr ($decrypted, 32, 32);

    my $sha256_of_data = sha256 ($raw_data);

    if ($sha256_of_data eq $checksum)
    {
      $data = $decrypted;
    }
  }

  my $encrypted = $cipher->encrypt ($data);

  my $hash = sprintf ("\$iwork\$%i\$%i\$%i\$%i\$%s\$%s\$%s", $hash_ver, $file_ver, $FORMAT, $iter, unpack ("H*", $salt), unpack ("H*", $iv), unpack ("H*", $encrypted));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 7) eq '$iwork$';

  my (undef, undef, $hash_ver, $file_ver, $format, $iter, $salt, $iv, $data) = split '\$', $hash;

  next unless (defined ($hash_ver));
  next unless (defined ($file_ver));
  next unless (defined ($format));
  next unless (defined ($iter));
  next unless (defined ($salt));
  next unless (defined ($iv));
  next unless (defined ($data));

  next unless (($hash_ver eq '1') or ($hash_ver eq '2'));
  next unless (($file_ver eq '1') or ($file_ver eq '2'));

  next unless ($format eq '1');

  $salt = pack ("H*", $salt);
  $iv   = pack ("H*", $iv);
  $data = pack ("H*", $data);

  $iter = int ($iter);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $hash_ver, $file_ver, $iter, $iv, $data);

  return ($new_hash, $word);
}

1;
