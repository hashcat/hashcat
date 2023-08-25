#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Crypt::Mode::ECB;
use Digest::SHA qw (sha256);

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub get_random_keepass_salt
{
  my $version = random_number (1, 2);

  my $algorithm;

  my $iteration;

  my $final_random_seed;

  if ($version == 1)
  {
    $algorithm = random_number (0, 1);

    $iteration = random_number (50000, 99999);

    $final_random_seed = random_bytes (16);
    $final_random_seed  = unpack ("H*", $final_random_seed);
  }
  elsif ($version == 2)
  {
    $algorithm = 0;

    $iteration = random_number (6000, 99999);

    $final_random_seed = random_bytes (32);
    $final_random_seed  = unpack ("H*", $final_random_seed);
  }

  my $transf_random_seed = random_bytes (32);
  $transf_random_seed = unpack ("H*", $transf_random_seed);

  my $enc_iv = random_bytes (16);
  $enc_iv = unpack ("H*", $enc_iv);

  my $contents_hash = random_bytes (32);
  $contents_hash = unpack ("H*", $contents_hash);

  my $inline_flag = 1;

  my $contents_len = random_number (128, 499);

  my $contents = random_bytes ($contents_len);

  $contents_len += 16 - $contents_len % 16;

  $contents = unpack ("H*", $contents);

  my $salt_buf;

  my $is_keyfile = random_number (0, 1);

  my $keyfile_attributes = "";

  if ($is_keyfile == 1)
  {
    $keyfile_attributes = $keyfile_attributes
                          . "1*64*"
                          . unpack ("H*", random_bytes (32));
  }

  if ($version == 1)
  {
    $salt_buf = $version   . '*' .
                $iteration . '*' .
                $algorithm . '*' .
                $final_random_seed  . '*' .
                $transf_random_seed . '*' .
                $enc_iv        . '*' .
                $contents_hash . '*' .
                $inline_flag   . '*' .
                $contents_len  . '*' .
                $contents      . '*' .
                $keyfile_attributes;
  }
  elsif ($version == 2)
  {
    $contents = random_bytes (32);
    $contents = unpack ("H*", $contents);

    $salt_buf = $version   . '*' .
                $iteration . '*' .
                $algorithm . '*' .
                $final_random_seed  . '*' .
                $transf_random_seed . '*' .
                $enc_iv        . '*' .
                $contents_hash . '*' .
                $contents      . '*' .
                $keyfile_attributes;
  }

  return $salt_buf;
}

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $param = shift;

  if (length $salt == 0)
  {
    $salt = get_random_keepass_salt ();
  }

  my @salt_arr = split ('\*', $salt);

  my $version   = $salt_arr[0];

  my $iteration = $salt_arr[1];

  my $algorithm = $salt_arr[2];

  my $final_random_seed  = $salt_arr[3];

  my $transf_random_seed = $salt_arr[4];

  my $enc_iv = $salt_arr[5];

  my $contents_hash;

  # specific to version 1
  my $inline_flag;
  my $contents_len;
  my $contents;

  # specific to version 2
  my $expected_bytes;

  # specific to keyfile handling
  my $inline_keyfile_flag;
  my $keyfile_len;
  my $keyfile_content;
  my $keyfile_attributes = "";

  $final_random_seed  = pack ("H*", $final_random_seed);

  $transf_random_seed = pack ("H*", $transf_random_seed);

  $enc_iv = pack ("H*", $enc_iv);

  my $intermediate_hash = sha256 ($word);

  if ($version == 1)
  {
    $contents_hash = $salt_arr[6];

    $contents_hash = pack ("H*", $contents_hash);

    $inline_flag   = $salt_arr[7];


    $contents_len  = $salt_arr[8];


    $contents      = $salt_arr[9];

    $contents      = pack ("H*", $contents);

    # keyfile handling
    if (scalar @salt_arr == 13)
    {
      $inline_keyfile_flag = $salt_arr[10];

      $keyfile_len         = $salt_arr[11];

      $keyfile_content     = $salt_arr[12];

      $keyfile_attributes = $keyfile_attributes
                          . "*" . $inline_keyfile_flag
                          . "*" . $keyfile_len
                          . "*" . $keyfile_content;

      $intermediate_hash = $intermediate_hash . pack ("H*", $keyfile_content);

      $intermediate_hash = sha256 ($intermediate_hash);
    }
  }
  elsif ($version == 2)
  {
    # keyfile handling
    if (scalar @salt_arr == 11)
    {
      $inline_keyfile_flag = $salt_arr[8];

      $keyfile_len         = $salt_arr[9];

      $keyfile_content     = $salt_arr[10];

      $intermediate_hash = $intermediate_hash . pack ("H*", $keyfile_content);

      $keyfile_attributes = $keyfile_attributes
                  . "*" . $inline_keyfile_flag
                  . "*" . $keyfile_len
                  . "*" . $keyfile_content;

    }

    $intermediate_hash = sha256 ($intermediate_hash);
  }

  my $aes = Crypt::Mode::ECB->new ('AES', 1);

  for (my $j = 0; $j < $iteration; $j++)
  {
    $intermediate_hash = $aes->encrypt ($intermediate_hash, $transf_random_seed);

    $intermediate_hash = substr ($intermediate_hash, 0, 32);
  }

  $intermediate_hash = sha256 ($intermediate_hash);

  my $final_key = sha256 ($final_random_seed . $intermediate_hash);

  my $final_algorithm;

  if ($version == 1 && $algorithm == 1)
  {
    $final_algorithm = "Crypt::Twofish";
  }
  else
  {
    $final_algorithm = "Crypt::Rijndael";
  }

  my $cipher;

  if ($version == 1)
  {
    $cipher = Crypt::CBC->new ({
                 key         => $final_key,
                 cipher      => $final_algorithm,
                 iv          => $enc_iv,
                 literal_key => 1,
                 header      => "none",
                 padding     => "standard",
                 keysize     => 32
               });
  }
  else
  {
    $cipher = Crypt::CBC->new ({
                 key         => $final_key,
                 cipher      => $final_algorithm,
                 iv          => $enc_iv,
                 literal_key => 1,
                 header      => "none",
                 padding     => "none",
                 keysize     => 32
               });
  }

  my $hash;

  if ($version == 1)
  {
    if (defined $param)
    {
      # if we try to verify the crack, we need to decrypt the contents instead of only encrypting it:

      $contents = $cipher->decrypt ($contents);

      # and check the output

      my $contents_hash_old = $contents_hash;

      $contents_hash = sha256 ($contents);

      if ($contents_hash_old ne $contents_hash)
      {
        # fake content
        $contents = "\x00" x length ($contents);
      }
    }
    else
    {
      $contents_hash = sha256 ($contents);
    }

    $contents = $cipher->encrypt ($contents);

    $hash = sprintf ('$keepass$*%d*%d*%d*%s*%s*%s*%s*%d*%d*%s%s',
          $version,
          $iteration,
          $algorithm,
          unpack ("H*", $final_random_seed),
          unpack ("H*", $transf_random_seed),
          unpack ("H*", $enc_iv),
          unpack ("H*", $contents_hash),
          $inline_flag,
          $contents_len,
          unpack ("H*", $contents),
          $keyfile_attributes);
  }
  if ($version == 2)
  {
    $expected_bytes = $salt_arr[6];

    $contents_hash = $salt_arr[7];
    $contents_hash = pack ("H*", $contents_hash);

    $expected_bytes = $cipher->decrypt ($contents_hash);

    $expected_bytes = substr ($expected_bytes . "\x00" x 32, 0, 32); # padding

    $hash = sprintf ('$keepass$*%d*%d*%d*%s*%s*%s*%s*%s%s',
          $version,
          $iteration,
          $algorithm,
          unpack ("H*", $final_random_seed),
          unpack ("H*", $transf_random_seed),
          unpack ("H*", $enc_iv),
          unpack ("H*", $expected_bytes),
          unpack ("H*", $contents_hash),
          $keyfile_attributes);
  }

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split ('\*', $hash_in);

  return unless (scalar @data == 9
              || scalar @data == 11
              || scalar @data == 12
              || scalar @data == 14);

  my $signature = shift @data;
  return unless ($signature eq '$keepass$');

  my $version = shift @data;
  return unless ($version == 1 || $version == 2);

  my $iteration          = shift @data;

  my $algorithm          = shift @data;

  my $final_random_seed  = shift @data;

  if ($version == 1)
  {
    return unless (length ($final_random_seed) == 32);
  }
  elsif ($version == 2)
  {
    return unless (length ($final_random_seed) == 64);
  }

  my $transf_random_seed = shift @data;
  return unless (length ($transf_random_seed) == 64);

  my $enc_iv = shift @data;
  return unless (length ($enc_iv) == 32);

  if ($version == 1)
  {
    my $contents_hash  = shift @data;
    return unless (length ($contents_hash) == 64);

    my $inline_flags   = shift @data;
    return unless ($inline_flags == 1);

    my $contents_len   = shift @data;

    my $contents       = shift @data;
    return unless (length ($contents) == $contents_len * 2);
  }
  elsif ($version == 2)
  {
    my $expected_bytes = shift @data;
    return unless (length ($expected_bytes) == 64);

    my $contents_hash  = shift @data;
    return unless (length ($contents_hash) == 64);
  }

  if (scalar @data == 12 || scalar @data == 14)
  {
    my $inline_flags = shift @data;
    return unless ($inline_flags == 1);

    my $keyfile_len  = shift @data;
    return unless ($keyfile_len == 64);

    my $keyfile     = shift @data;
    return unless (length ($keyfile) == $keyfile_len);
  }

  my $salt = substr ($hash_in, length ("*keepass*") + 1);
  my $param = 1; # distinguish between encrypting vs decrypting

  return unless defined $salt;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $param);

  return ($new_hash, $word);
}

1;
