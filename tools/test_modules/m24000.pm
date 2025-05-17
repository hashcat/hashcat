#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::ScryptKDF qw (scrypt_raw);
use Digest::SHA qw (sha256);
use Crypt::CBC;
use Crypt::Rijndael;
use Crypt::Twofish;
use Crypt::Cipher::Serpent; # Crypt::Serpent doesn't work for me :(
use Crypt::Camellia;

sub module_constraints { [[0, 256], [24, 24], [-1, -1], [-1, -1], [-1, -1]] }

my $SCRYPT_N = 32768;
my $SCRYPT_R =    16;
my $SCRYPT_P =     1;

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $data = shift;
  my $type = shift;

  # most heavy part of the algorithm:

  my $key = scrypt_raw ($word, $salt, $SCRYPT_N, $SCRYPT_R, $SCRYPT_P, 32);

  my %crypto_types = (
     8 => 'Crypt::Rijndael',        # '08' => AES
     9 => 'Crypt::Twofish',         # '09' => Twofish
    10 => 'Crypt::Cipher::Serpent', # '0a' => Serpent
    15 => 'Crypt::Camellia'         # '0f' => Camellia
  );

  my @crypto_type_conv = (8, 9, 10, 15);

  if (! defined ($type))
  {
    my $rand_type_num = random_number (0, 3);

    $type = $crypto_type_conv[$rand_type_num];
  }

  my $crypto_algo = $crypto_types{$type};

  my $crypt = Crypt::CBC->new ({
    cipher      => $crypto_algo,
    key         => $key,
    iv          => "\x00" x 16,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  if (defined ($data)) # decrypt
  {
    my $plain_text = $crypt->decrypt ($data);

    my $part1 = substr ($plain_text,  0, 64);
    my $part2 = substr ($plain_text, 64, 32);

    my $hash = sha256 ($part1);

    if ($hash ne $part2) # wrong => fake the data
    {
      $data = "\x00" x length ($data); # 64 + 32 = 96
    }
  }
  else # encrypt
  {
    $data = random_bytes (64);

    my $hash = sha256 ($data);

    $data = $crypt->encrypt ($data . $hash);
  }

  return sprintf ("\$bcve\$4\$%02x\$%s\$%s", $type, unpack ("H*", $salt), unpack ("H*", $data));
}

sub module_verify_hash
{
  my $line = shift;

  my $idx1 = index ($line, ':');

  return if ($idx1 < 1);

  my $hash = substr ($line, 0, $idx1);
  my $word = substr ($line, $idx1 + 1);

  return if (substr ($hash, 0, 8) ne "\$bcve\$4\$");

  $idx1 = index ($hash, '$', 8);

  return if ($idx1 < 1);

  # crypto type

  my $crypto_type = substr ($hash, 8, $idx1 - 8);

  return unless ($crypto_type eq "08") ||
                ($crypto_type eq "09") ||
                ($crypto_type eq "0a") ||
                ($crypto_type eq "0f");

  $crypto_type = hex ($crypto_type);

  # salt

  my $idx2 = index ($hash, '$', $idx1 + 1);

  my $salt = substr ($hash, $idx1 + 1, $idx2 - $idx1 - 1);

  return unless ($salt =~ m/^[0-9a-fA-F]+$/);

  # data

  my $data = substr ($hash, $idx2 + 1);

  return unless ($data =~ m/^[0-9a-fA-F]+$/);

  # convert to hex:

  $salt = pack ("H*", $salt);
  $data = pack ("H*", $data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $data, $crypto_type);

  return ($new_hash, $word);
}

1;
