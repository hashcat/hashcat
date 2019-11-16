#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum::CTX;

use Digest::SHA  qw (sha256 sha512);
use Digest::HMAC qw (hmac_hex);

use Crypt::CBC;
use Compress::Zlib;

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

my $MAX_DATA_LEN = 16384;

# helper function: key derivation from password and one point on the curve (public key)

sub generate_key
{
  my $word = shift;
  my $ephemeral_pubkey = shift;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => 1024,
    output_len => 64
  );

  my $private_key = $pbkdf2->PBKDF2 ("", $word);

  my $method = Crypt::OpenSSL::EC::EC_GFp_simple_method (); # or Crypt::OpenSSL::EC::EC_GFp_mont_method ()

  my $group = Crypt::OpenSSL::EC::EC_GROUP::new ($method);

  # secp256k1 elliptic curve parameters

  my $p = Crypt::OpenSSL::Bignum->new_from_hex ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
  my $a = Crypt::OpenSSL::Bignum->new_from_hex ("0000000000000000000000000000000000000000000000000000000000000000");
  my $b = Crypt::OpenSSL::Bignum->new_from_hex ("0000000000000000000000000000000000000000000000000000000000000007");

  my $ctx = Crypt::OpenSSL::Bignum::CTX->new ();

  Crypt::OpenSSL::EC::EC_GROUP::set_curve_GFp ($group, $p, $a, $b, $ctx);

  my $Gx = Crypt::OpenSSL::Bignum->new_from_hex ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  my $Gy = Crypt::OpenSSL::Bignum->new_from_hex ("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

  my $G = Crypt::OpenSSL::EC::EC_POINT::new ($group);

  Crypt::OpenSSL::EC::EC_POINT::set_affine_coordinates_GFp ($group, $G, $Gx, $Gy, $ctx);

  my $order    = Crypt::OpenSSL::Bignum->new_from_hex ("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  my $cofactor = Crypt::OpenSSL::Bignum->new_from_hex ("0000000000000000000000000000000000000000000000000000000000000001");

  Crypt::OpenSSL::EC::EC_GROUP::set_generator ($group, $G, $order, $cofactor); # or cofactor = Crypt::OpenSSL::Bignum->one ()


  # scalar

  # hash mod GROUP_ORDER

  my $m = Crypt::OpenSSL::Bignum->new_from_hex (unpack ("H*", $private_key));


  # point (public key, ephemeral_pubkey)

  my $Q = Crypt::OpenSSL::EC::EC_POINT::new ($group);

  my $ret = Crypt::OpenSSL::EC::EC_POINT::oct2point ($group, $Q, $ephemeral_pubkey, $ctx);

  if ($ret == 0)
  {
    return;
  }

  # multiply

  my $result = Crypt::OpenSSL::EC::EC_POINT::new ($group);

  my $n = Crypt::OpenSSL::Bignum->zero ();

  Crypt::OpenSSL::EC::EC_POINT::mul ($group, $result, $n, $Q, $m, $ctx);

  # get compressed public/shared key format

  my $public_key = Crypt::OpenSSL::EC::EC_POINT::point2oct ($group, $result, &Crypt::OpenSSL::EC::POINT_CONVERSION_COMPRESSED, $ctx);


  # hash the compressed public key with sha512 ()

  return sha512 ($public_key);
}

sub module_generate_hash
{
  my $word = shift;

  my $ephemeral_pubkey = "";
  my $key = "";

  my $valid_point = 0;

  while ($valid_point == 0)
  {
    my $sign_of_curve_point = int (rand (2)); # 2 possibilities: 02... or 03... ephemeral public keys

    $ephemeral_pubkey = pack ("H*", "0" . ($sign_of_curve_point + 2) . random_hex_string (64));

    $key = generate_key ($word, $ephemeral_pubkey);

    if (defined ($key))
    {
      $valid_point = 1;
    }
  }

  my $valid_compression_rate = 0;

  my $compressed_data = "";

  while ($valid_compression_rate == 0)
  {
    my $data_buf = "{\r\n    \"";

    if (int (rand (2)) == 1) # alternative with different line break
    {
      $data_buf = "{\n    \"";
    }

    # we assume a compression rate of 30% (smaller if compressed)

    my $data_length = 64 + int (rand (int ($MAX_DATA_LEN * 1.30 + 1)));

    my $random_length = $data_length - length ($data_buf);

    if ($random_length > 0)
    {
      $data_buf .= random_string ($random_length); # or random_bytes ($random_length);
    }

    # compress/deflate the data:

    my $deflator = deflateInit (-WindowBits => MAX_WBITS);

    my $header = $deflator->deflate ($data_buf);

    $compressed_data = $deflator->flush ();

    $compressed_data = $header . $compressed_data;

    # check if data is valid:

    my $compressed_data_len = length ($compressed_data);

    if ($compressed_data_len < 64) # minimum length required by hashcat's tokenizer
    {
      next;
    }

    if (($compressed_data_len + 15) > $MAX_DATA_LEN) # version 5 is not supported in -m 21700
    {
      next;
    }

    $valid_compression_rate = 1;
  }


  # encrypt the data with AES128:

  my $iv      = substr ($key,  0, 16);
  my $aes_key = substr ($key, 16, 16);

  my $aes = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    keysize     => 16,
    literal_key => 1,
    header      => "none",
    iv          => $iv,
    key         => $aes_key
  });

  my $encrypted_data = $aes->encrypt ($compressed_data);


  # MAC:

  my $hmac_key = substr ($key, 32, 32);

  my $mac = hmac_hex ($encrypted_data, $hmac_key, \&sha256);

  # format the hash:

  my $hash = sprintf ("\$electrum\$4*%s*%s*%s",
    unpack ("H*", $ephemeral_pubkey),
    unpack ("H*", $encrypted_data),
    $mac
  );

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $hash_in = substr ($line, 0, $index1);

  my $word = substr ($line, $index1 + 1);

  return if (substr ($hash_in, 0, 10) ne "\$electrum\$");


  # version:

  my $index2 = index ($hash_in, "*");

  return if $index2 < 1;

  my $version = substr ($hash_in, 10, $index2 - 10);

  return if ($version ne "4");


  # public key:

  $index1 = index ($line, "*", $index2 + 1);

  return if $index1 < 1;

  my $ephemeral_pubkey = substr ($hash_in, $index2 + 1, $index1 - $index2 - 1);

  $ephemeral_pubkey = pack ("H*", $ephemeral_pubkey);


  # data:

  $index2 = index ($hash_in, "*", $index1 + 1);

  return if $index2 < 1;

  my $data_buf = substr ($hash_in, $index1 + 1, $index2 - $index1 - 1);

  $data_buf = pack ("H*", $data_buf);


  # MAC:

  my $mac = substr ($hash_in, $index2 + 1);


  # Start:

  my $new_hash = "";

  my $key = generate_key ($word, $ephemeral_pubkey);

  my $hmac_key = substr ($key, 32, 32);

  my $mac_gen = hmac_hex ($data_buf, $hmac_key, \&sha256);

  if ($mac_gen eq $mac)
  {
    $new_hash = $hash_in;
  }

  return ($new_hash, $word);
}

1;
