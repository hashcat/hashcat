#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Crypt::ECB  qw (encrypt);
use Digest::MD4 qw (md4);
use Digest::SHA qw (sha1 hmac_sha1 hmac_sha512);
use Encode;

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub get_random_dpapimk_salt
{
  my $version = shift;

  my $salt_buf = "";

  my $context = random_number (1, 2);

  my $cipher_algo = "";

  my $hash_algo = "";

  my $iterations;

  my $SID = sprintf ('S-15-21-%d-%d-%d-%d',
             random_number (400000000,490000000),
             random_number (400000000,490000000),
             random_number (400000000,490000000),
             random_number (1000,1999));

  my $cipher_len = 0;

  if ($version == 1)
  {
    $iterations = random_number (4000, 24000);

    $cipher_algo = "des3";

    $hash_algo = "sha1";

    $cipher_len = 208;
  }
  elsif ($version == 2)
  {
    $iterations = random_number (8000, 17000);

    $cipher_algo = "aes256";

    $hash_algo = "sha512";

    $cipher_len = 288;
  }

  my $iv = random_bytes (16);
  $iv    = unpack ("H*", $iv);

  $salt_buf = $version . '*' .
              $context . '*' .
              $SID     . '*' .
              $cipher_algo   . '*' .
              $hash_algo     . '*' .
              $iterations    . '*' .
              $iv         . '*' .
              $cipher_len . '*';

  return $salt_buf;
}

#Thanks to Jochen Hoenicke <hoenicke@gmail.com>
# (one of the authors of Palm Keyring)
# for these next two subs.
sub dpapi_pbkdf2
{
    my ($password, $salt, $iter, $keylen, $prf) = @_;
    my ($k, $t, $u, $ui, $i);
    $t = "";
    for ($k = 1; length ($t) <  $keylen; $k++)
    {
      $u = $ui = &$prf ($salt.pack ('N', $k), $password);
      for ($i = 1; $i < $iter; $i++)
      {
        # modification to fit Microsoft
        # weird pbkdf2 implementation...
        $ui = &$prf ($u, $password);
        $u ^= $ui;
      }
      $t .= $u;
    }
    return substr ($t, 0, $keylen);
}

sub module_generate_hash
{
  my $word_buf     = shift;
  my $salt_buf     = shift;
  my $dpapimk_salt = shift // get_random_dpapimk_salt (2);
  my $cipher       = shift;

  my @salt_arr = split ('\*', $dpapimk_salt);

  my $version          = $salt_arr[0];
  my $context          = $salt_arr[1];
  my $SID              = $salt_arr[2];
  my $cipher_algorithm = $salt_arr[3];
  my $hash_algorithm   = $salt_arr[4];
  my $iterations       = $salt_arr[5];
  my $salt             = pack ("H*", $salt_arr[6]);
  my $cipher_len       = $salt_arr[7];

  # intermediate values

  my $user_hash;
  my $user_derivationKey;
  my $encKey;
  my $expected_hmac;
  my $cleartext;

  if ($context == 1)
  {
     $user_hash = sha1 (encode ("UTF-16LE", $word_buf));
  }
  elsif ($context == 2)
  {
     $user_hash = md4 (encode ("UTF-16LE", $word_buf));
  }

  $user_derivationKey = hmac_sha1 (encode ("UTF-16LE", $SID . "\x00"), $user_hash);

  my $hmacSalt = random_bytes (16);
  my $last_key = random_bytes (64);

  if ($version == 1)
  {
    $encKey        = hmac_sha1 ($hmacSalt, $user_derivationKey);
    $expected_hmac = hmac_sha1 ($last_key, $encKey);

    # need padding because keyLen is 24 and hashLen 20
    $expected_hmac = $expected_hmac . random_bytes (4);
  }
  elsif ($version == 2)
  {
    $encKey        = hmac_sha512 ($hmacSalt, $user_derivationKey);
    $expected_hmac = hmac_sha512 ($last_key, $encKey);
  }

  $cleartext = $hmacSalt . $expected_hmac . $last_key;

  my $derived_key;
  my $key;
  my $iv;

  my $pbkdf2;

  if ($version == 1)
  {
    $derived_key = dpapi_pbkdf2 ($user_derivationKey, $salt, $iterations, 32, \&hmac_sha1);
  }
  elsif ($version == 2)
  {
    $derived_key = dpapi_pbkdf2 ($user_derivationKey, $salt, $iterations, 48, \&hmac_sha512);
  }

  if (defined $cipher)
  {
    $cipher = pack ("H*", $cipher);

    my $computed_hmac = "";

    if ($version == 1)
    {
      $key = substr ($derived_key,   0, 24);
      $iv  = substr ($derived_key,  24,  8);

      my $p1 = Crypt::ECB->new ({
        key         => substr ($key, 0, 8),
        cipher      => "DES",
        literal_key => 1,
        header      => "none",
        keysize     => 8,
        padding     => "null",
      });

      my $p2 = Crypt::ECB->new ({
        key         => substr ($key, 8, 8),
        cipher      => "DES",
        literal_key => 1,
        header      => "none",
        keysize     => 8,
        padding     => "null",
      });

      my $p3 = Crypt::ECB->new ({
        key         => substr ($key, 16, 8),
        cipher      => "DES",
        literal_key => 1,
        header      => "none",
        keysize     => 8,
        padding     => "null",
      });

      # let's compute a 3DES-EDE-CBC decryption

      my $out1;
      my $out2;
      my $out3;
      my $expected_cleartext = "";

      # size of cipherlen is 104 bytes
      for (my $k = 0; $k < 13; $k++)
      {
        $out1 = $p3->decrypt (substr ($cipher, $k * 8, 8));
        $out2 = $p2->encrypt ($out1);
        $out3 = $p1->decrypt ($out2);

        $expected_cleartext .= substr ($out3, 0, 8) ^ $iv;

        $iv = substr ($cipher, $k * 8, 8);
      }

      $last_key      = substr ($expected_cleartext,  length ($expected_cleartext) - 64, 64);
      $hmacSalt      = substr ($expected_cleartext, 0, 16);
      $expected_hmac = substr ($expected_cleartext, 16, 20);

      $encKey        = hmac_sha1 ($hmacSalt, $user_derivationKey);
      $computed_hmac = hmac_sha1 ($last_key, $encKey);

      $cleartext = $expected_cleartext;

      if (unpack ("H*", $expected_hmac) ne unpack ("H*", $computed_hmac))
      {
        $cleartext = "0" x 104;
      }
    }
    elsif ($version == 2)
    {
      $key = substr ($derived_key,  0, 32);
      $iv  = substr ($derived_key, 32, 16);

      my $aes = Crypt::CBC->new ({
        key         => $key,
        cipher      => "Crypt::Rijndael",
        iv          => $iv,
        literal_key => 1,
        header      => "none",
        keysize     => 32,
        padding     => "null",
      });

      my $expected_cleartext = $aes->decrypt ($cipher);

      $last_key      = substr ($expected_cleartext,  length ($expected_cleartext) - 64, 64);
      $hmacSalt      = substr ($expected_cleartext, 0, 16);
      $expected_hmac = substr ($expected_cleartext, 16, 64);

      $encKey        = hmac_sha512 ($hmacSalt, $user_derivationKey);
      $computed_hmac = hmac_sha512 ($last_key, $encKey);

      $cleartext = $expected_cleartext;

      if (unpack ("H*", $expected_hmac) ne unpack ("H*", $computed_hmac))
      {
        $cleartext = "0" x 144;
      }
    }
  }

  if ($version == 1)
  {
    $key = substr ($derived_key,   0, 24);
    $iv  = substr ($derived_key,  24,  8);

    my $p1 = Crypt::ECB->new ({
      key         => substr ($key, 0, 8),
      cipher      => "DES",
      literal_key => 1,
      header      => "none",
      keysize     => 8,
      padding     => "null",
    });

    my $p2 = Crypt::ECB->new ({
      key         => substr ($key, 8, 8),
      cipher      => "DES",
      literal_key => 1,
      header      => "none",
      keysize     => 8,
      padding     => "null",
    });

    my $p3 = Crypt::ECB->new ({
      key         => substr ($key, 16, 8),
      cipher      => "DES",
      literal_key => 1,
      header      => "none",
      keysize     => 8,
      padding     => "null",
    });

    # let's compute a 3DES-EDE-CBC encryption

    # compute first block
    my $out1 = $p1->encrypt (substr ($cleartext, 0, 8) ^ $iv);
    my $out2 = $p2->decrypt ($out1);
    my $out3 = $p3->encrypt ($out2);

    $cipher = substr ($out3, 0, 8);

    # size of cipherlen is 104 bytes
    for (my $k = 1; $k < 13; $k++)
    {
      $iv = $out3;

      $out1 = $p1->encrypt (substr ($cleartext, $k * 8, 8) ^ $iv);
      $out2 = $p2->decrypt ($out1);
      $out3 = $p3->encrypt ($out2);

      $cipher .= substr ($out3, 0, 8);
    }
  }
  else
  {
    $key = substr ($derived_key,  0, 32);
    $iv  = substr ($derived_key, 32, 16);

    my $aes = Crypt::CBC->new ({
      key         => $key,
      cipher      => "Crypt::Rijndael",
      iv          => $iv,
      literal_key => 1,
      header      => "none",
      keysize     => 32,
      padding     => "null",
    });

    $cipher = $aes->encrypt ($cleartext);
  }

  my $tmp_hash = sprintf ('$DPAPImk$%d*%d*%s*%s*%s*%d*%s*%d*%s',
                 $version,
                 $context,
                 $SID,
                 $cipher_algorithm,
                 $hash_algorithm,
                 $iterations,
                 unpack ("H*", $salt),
                 $cipher_len,
                 unpack ("H*", $cipher));

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @tmp_data = split ('\$', $hash);

  my $signature = $tmp_data[1];

  return unless ($signature eq 'DPAPImk');

  my @data = split ('\*', $tmp_data[2]);

  return unless (scalar @data == 9);

  my $version = shift @data;

  return unless ($version == 1 || $version == 2);

  my $context          = shift @data;
  my $SID              = shift @data;
  my $cipher_algorithm = shift @data;
  my $hash_algorithm   = shift @data;
  my $iteration        = shift @data;
  my $iv               = shift @data;
  my $cipher_len       = shift @data;
  my $cipher           = shift @data;

  return unless (length ($cipher) == $cipher_len);

  if ($version == 1)
  {
    return unless ($cipher_len == 208);
  }
  elsif ($version == 2)
  {
    return unless ($cipher_len == 288);
  }

  my $dpapimk_salt = substr ($hash, length ('$DPAPImk$'));

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $dpapimk_salt, $cipher);

  return ($new_hash, $word);
}

1;
