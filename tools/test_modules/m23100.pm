#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::CBC;

sub module_constraints { [[0, 256], [20, 20], [-1, -1], [-1, -1], [-1, -1]] }

my $ITERATIONS    = 1000;
my $FIXED_PADDING = "\x04\x04\x04\x04";

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iv   = shift;
  my $data = shift;

  my $kdf = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $ITERATIONS,
    output_len => 24
  );

  my $key = $kdf->PBKDF2 ($salt, $word);

  my $key1 = substr ($key,  0, 8);
  my $key2 = substr ($key,  8, 8);
  my $key3 = substr ($key, 16, 8);

  my $iv0 = "\x00" x 8; # not the real IV (see XOR with correct IV in main loop below)

  my $des1 = Crypt::CBC->new ({
    key         => $key1,
    iv          => $iv0,
    cipher      => "DES",
    literal_key => 1,
    header      => "none",
    padding     => "none",
  });

  my $des2 = Crypt::CBC->new ({
    key         => $key2,
    iv          => $iv0,
    cipher      => "DES",
    literal_key => 1,
    header      => "none",
    padding     => "none",
  });

  my $des3 = Crypt::CBC->new ({
    key         => $key3,
    iv          => $iv0,
    cipher      => "DES",
    literal_key => 1,
    header      => "none",
    padding     => "none",
  });

  my $data_encrypted = "";

  if (defined ($data))
  {
    my $iv = substr ($data, 32, 8); # yeah, we do NOT need the original IV (only last block)
    my $d  = substr ($data, 40, 8);

    my $t;

    $t = $des3->decrypt ($d);
    $t = $des2->encrypt ($t);
    $t = $des1->decrypt ($t);

    $t ^= $iv;

    if (substr ($t, 4, 4) eq $FIXED_PADDING)
    {
      $data_encrypted = $data;
    }
  }
  else
  {
    $iv   = random_bytes ( 8);
    $data = random_bytes (44);

    $data .= $FIXED_PADDING;

    my $c = $iv; # temporary variable to hold latest "IV"

    # fixed 48 byte data length:

    for (my ($i, $j) = (0, 0); $i < 6; $i += 1, $j += 8)
    {
      my $d = substr ($data, $j, 8);

      $d ^= $c;

      my $t;

      $t = $des1->encrypt ($d);
      $t = $des2->decrypt ($t);
      $t = $des3->encrypt ($t);

      $data_encrypted .= $t;

      $c = $t
    }
  }

  my $hash = sprintf ("\$keychain\$*%s*%s*%s",
    unpack ("H*", $salt),
    unpack ("H*", $iv),
    unpack ("H*", $data_encrypted)
  );

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 11) eq "\$keychain\$*");

  # salt

  my $idx1 = index ($line, "*", 11);

  return if ($idx1 < 1);

  my $salt = substr ($line, 11, $idx1 - 11);

  return if (length ($salt) != 40);

  # iv

  my $idx2 = index ($line, "*", $idx1 + 1);

  return if ($idx2 < 1);

  my $iv = substr ($line, $idx1 + 1,  $idx2 - $idx1 - 1);

  return if (length ($iv) != 16);

  # data

  $idx1 = index ($line, ":", $idx2 + 1);

  return if ($idx1 < 1);

  my $data = substr ($line, $idx2 + 1, $idx1 - $idx2 - 1);

  return if (length ($data) != 96);

  # word

  my $word = substr ($line, $idx1 + 1);

  # hex decode:

  $salt = pack ("H*", $salt);
  $iv   = pack ("H*", $iv);
  $data = pack ("H*", $data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iv, $data);

  return ($new_hash, $word);
}

1;
