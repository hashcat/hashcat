#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::ScryptKDF qw (scrypt_raw);
use Encode;
use Crypt::CBC;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

my $SCRYPT_N = 16384;
my $SCRYPT_R =     8;
my $SCRYPT_P =     1;

my $FIXED_SALT = pack ("H*", "3551038075a3b0c5");
my $FIXED_IV   = pack ("H*", "a344391f538311b329548616c489723e");

my $BITCOINJ_CHARS = ".abcdefghijklmnopqrstuvwxyz";

sub verify_bitcoinj
{
  my $data = shift;

  my $first_char = substr ($data, 0, 1);

  return 0 if ($first_char ne "\n");

  my $second_char = substr ($data, 1, 1);

  return 0 if (ord ($second_char) >= 128);

  return 0 if (substr ($data, 2, 4) ne "org.");

  for (my $i = 6; $i < 14; $i++) # start with 6 (we already checked first chars)
  {
    my $c = substr ($data, $i, 1);

    my $idx = index ($BITCOINJ_CHARS, $c);

    next if ($idx >= 0);

    return 0; # fail
  }

  return 1; # success
}

sub module_generate_hash
{
  my $word   = shift;
  my $iv     = shift;
  my $block1 = shift;
  my $block2 = shift;

  my $word_utf16be = encode ('UTF-16BE', $word);

  my $key = scrypt_raw ($word_utf16be, $FIXED_SALT, $SCRYPT_N, $SCRYPT_R, $SCRYPT_P, 32);

  my $aes_cbc1 = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    iv          => $iv,
    key         => $key,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  my $aes_cbc2 = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    iv          => $FIXED_IV,
    key         => $key,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  my $data_block1 = "";
  my $data_block2 = "";

  if (defined ($block1)) # verify
  {
    # note: we need to try both alternatives (if the first fails)

    my $data_dec = $aes_cbc1->decrypt ($block1);

    if (verify_bitcoinj ($data_dec) == 1)
    {
      $data_block1 = $block1;
      $data_block2 = $block2;
    }
    else
    {
      # else: ALTERNATIVE 2 (block 2, fixed IV):

      $data_dec = $aes_cbc2->decrypt ($block2);

      if (verify_bitcoinj ($data_dec) == 1)
      {
        $data_block1 = $block1;
        $data_block2 = $block2;
      }
    }
  }
  else
  {
    my $data = "";

    $data .= "\n";
    $data .= chr (random_number (0, 127));
    $data .= "org.";

    for (my $i = 6; $i < 16; $i++)
    {
      $data .= substr ($BITCOINJ_CHARS, random_number (0, length ($BITCOINJ_CHARS) - 1), 1);
    }

    my $random_alternative = random_number (0, 1);

    my $data_enc = "";

    if ($random_alternative == 0)
    {
      $data_block1 = $aes_cbc1->encrypt ($data);
      $data_block2 = $iv; # fake
    }
    else
    {
      $data_block1 = $iv; # fake
      $data_block2 = $aes_cbc2->encrypt ($data);
    }
  }

  my $hash = sprintf ("\$multibit\$2*%s*%s*%s", unpack ("H*", $iv), unpack ("H*", $data_block1), unpack ("H*", $data_block2));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 12) eq '$multibit$2*');

  # split hash and word:

  my $idx1 = index ($line, ":", 12);

  return if $idx1 < 1;

  my $hash = substr ($line,  0, $idx1);
  my $word = substr ($line, $idx1 + 1);

  # IV:

  my $idx2 = index ($hash, "*", 12);

  my $iv = substr ($hash, 12, $idx2 - 12);

  # block 1:

  $idx1 = index ($hash, "*", $idx2 + 1);

  my $block1 = substr ($hash, $idx2 + 1, $idx1 - $idx2 - 1);

  # block 2:

  my $block2 = substr ($hash, $idx1 + 1);

  return unless $iv     =~ m/^[0-9a-fA-F]{32}$/;
  return unless $block1 =~ m/^[0-9a-fA-F]{32}$/;
  return unless $block2 =~ m/^[0-9a-fA-F]{32}$/;

  # hex to binary/raw:

  $iv     = pack ("H*", $iv);
  $block1 = pack ("H*", $block1);
  $block2 = pack ("H*", $block2);

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $iv, $block1, $block2);

  return ($new_hash, $word);
}

1;
